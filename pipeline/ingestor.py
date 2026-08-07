#!/usr/bin/env python3
"""
Pipeline / Ingestor.

Tails the sensor JSON logs on the read-only volume, normalizes each record to the
canonical event schema, then:
  * XADD -> redis stream "events"      (consumed by analytics)
  * INSERT -> postgres events hypertable
  * upsert ips; first-seen IPs -> redis stream "enrich:queue" (consumed by enrichment)

This is the ONE place that knows each sensor's native format. Add a sensor by adding
a normalizer; nothing downstream changes.
"""
import asyncio
import contextlib
import ipaddress
import json
import os
import signal
import time
import uuid
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as redis

import heartbeat
import retry

LOG_DIR = os.environ.get("LOG_DIR", "/data/logs")
# Where per-file read offsets are persisted. The log volume is mounted
# read-only (it is a one-way boundary), so checkpoints need their own writable
# volume; see the pipeline service in docker-compose.yml.
STATE_DIR = os.environ.get("STATE_DIR", "/var/lib/pipeline")
# Bound on how much gets re-read after an unclean stop. A checkpoint is also
# written whenever a tail catches up to the end of its file, so in steady state
# (which is idle far more often than not) the real replay window is one line.
CHECKPOINT_EVERY_LINES = int(os.environ.get("CHECKPOINT_EVERY_LINES", "1000"))
# Namespace for deterministic event ids — see _event_id().
_EVENT_NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")
# This sensor's own public IP(s), comma-separated. Suricata response-direction
# rules ("ET SCAN ... attempt response" etc.) fire on the honeypot's own replies
# with src_ip = this host and dst_port = the attacker's ephemeral port, which
# downstream scan correlation misreads as the sensor port-scanning itself.
SELF_IPS = frozenset(
    ip.strip()
    for ip in os.environ.get("SENSOR_PUBLIC_IP", "").split(",") if ip.strip())
# Drop RFC1918/loopback/link-local sources. Nothing routable on the public
# internet can reach the sensors from these ranges — in practice they are the
# host probing its own honeypot (localhost curl/ssh arrives NAT'd as the Docker
# bridge gateway, e.g. 172.21.0.1) or container-to-container chatter. Left in,
# they surface as phantom "sweep" rows in scan correlation, because one probe
# per service looks exactly like a port sweep. Set DROP_PRIVATE_SRC=0 if this
# sensor is ever deployed to watch an internal segment on purpose.
#
# Listed explicitly rather than using ipaddress.is_private, which also covers
# the TEST-NET documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24) — those are what the tests use for synthetic attacker IPs,
# and dropping them would silently gut the fixtures.
PRIVATE_SRC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "127.0.0.0/8", "169.254.0.0/16",                   # loopback, link-local
    "::1/128", "fe80::/10", "fc00::/7",                # IPv6 equivalents
))
DROP_PRIVATE_SRC = os.environ.get("DROP_PRIVATE_SRC", "1").lower() not in ("0", "false", "no")


def _is_private_src(parsed_ip) -> bool:
    return any(parsed_ip in net for net in PRIVATE_SRC_NETS
               if net.version == parsed_ip.version)
FILES = {
    "cowrie.json": "cowrie",
    "eve.json": "suricata",
    "extra.json": "extra",
}
EVENTS_STREAM = "events"
ENRICH_STREAM = "enrich:queue"

# ───────────────────────── runtime tuning ─────────────────────────
# Backlog between the tails and the consumers. This is the ingestor's memory
# ceiling in practice: a Suricata alert carries its payload, so a queued record
# is kilobytes, not bytes, and the old 10000 slots could hold ~40 MB of raw
# records during a flood — which CPython then keeps resident long after the
# flood, since freed arenas are not handed back to the OS. A full queue is not
# data loss: the tails block on put(), stop advancing, and the sensor logs
# themselves are the buffer.
QUEUE_MAX = int(os.environ.get("INGEST_QUEUE_MAX") or 2000)
CONSUMERS = int(os.environ.get("INGEST_CONSUMERS") or 3)
# Per-record retries before an event is given up on. Only transient failures
# (see retry.is_transient) are retried; a malformed record is skipped at once.
ITEM_MAX_ATTEMPTS = int(os.environ.get("INGEST_ITEM_MAX_ATTEMPTS") or 4)
# How long a consumer waits on an empty queue before beating anyway. An idle
# ingestor is healthy, and must not read as wedged.
IDLE_BEAT_S = 5.0
# Seconds to let the consumers drain the queue after SIGTERM.
SHUTDOWN_DRAIN_S = float(os.environ.get("SHUTDOWN_DRAIN_S") or 10.0)
# A loop that survived this long before failing gets a fresh backoff sequence
# rather than inheriting the previous one.
BACKOFF_RESET_S = 300.0

REDIS_SOCKET_TIMEOUT_S = float(os.environ.get("REDIS_SOCKET_TIMEOUT_S") or 30.0)
REDIS_CONNECT_TIMEOUT_S = float(os.environ.get("REDIS_CONNECT_TIMEOUT_S") or 10.0)
PG_COMMAND_TIMEOUT_S = float(os.environ.get("PG_COMMAND_TIMEOUT_S") or 30.0)
PG_CONNECT_TIMEOUT_S = float(os.environ.get("PG_CONNECT_TIMEOUT_S") or 10.0)

# Liveness thresholds, one per concurrent loop — see heartbeat.py. The consumer
# threshold must clear BACKOFF_MAX_S plus a retry cycle, or a Postgres outage
# (during which the consumers are working exactly as intended) would look like
# a hang and restart the worker for no reason.
HEARTBEATS = {f"tail:{name}": heartbeat.env_seconds("PIPELINE_TAIL_STALE_S", 60)
              for name in FILES}
HEARTBEATS.update({
    f"consumer:{i}": heartbeat.env_seconds("PIPELINE_CONSUMER_STALE_S", 120)
    for i in range(CONSUMERS)})


# ───────────────────────── normalizers ─────────────────────────
def _base():
    return {
        "event_id": str(uuid.uuid4()), "ts": None, "sensor": None, "service": None,
        "event_type": None, "src_ip": None, "src_port": None, "dst_port": None,
        "username": None, "password": None, "command": None, "signature": None,
        "severity": 0, "session": None, "raw": None,
    }


COWRIE_MAP = {
    "cowrie.session.connect": ("connect", None),
    "cowrie.login.failed": ("login_attempt", None),
    "cowrie.login.success": ("login_success", None),
    "cowrie.command.input": ("command", None),
    "cowrie.command.failed": ("command", None),
    "cowrie.session.file_download": ("file", None),
    "cowrie.session.file_upload": ("file", None),
    "cowrie.client.version": ("connect", None),
}


def norm_cowrie(r: dict):
    e = _base()
    e["sensor"] = "cowrie"
    e["ts"] = r.get("timestamp")
    e["src_ip"] = r.get("src_ip")
    e["src_port"] = r.get("src_port")
    e["dst_port"] = r.get("dst_port")
    e["username"] = r.get("username")
    e["password"] = r.get("password")
    e["command"] = r.get("input")
    e["session"] = r.get("session")
    eventid = r.get("eventid", "")
    e["service"] = "ssh"
    e["event_type"] = COWRIE_MAP.get(eventid, ("event", None))[0]
    if eventid == "cowrie.client.version":
        e["signature"] = r.get("version")
    e["raw"] = r
    if not e["ts"] or not e["src_ip"]:
        return None
    return e


def norm_suricata(r: dict):
    et = r.get("event_type")
    if et not in ("alert", "http", "anomaly"):
        return None  # flows/dns/tls are stored by suricata itself; we want signal
    e = _base()
    e["sensor"] = "suricata"
    e["ts"] = r.get("timestamp")
    e["src_ip"] = r.get("src_ip")
    e["src_port"] = r.get("src_port")
    e["dst_port"] = r.get("dest_port")
    e["service"] = r.get("app_proto") or _svc_from_port(r.get("dest_port"))
    e["raw"] = r
    if et == "alert":
        a = r.get("alert", {})
        e["event_type"] = "alert"
        e["signature"] = a.get("signature")
        e["severity"] = a.get("severity", 2)
    elif et == "http":
        e["event_type"] = "connect"
        h = r.get("http", {})
        e["command"] = f'{h.get("http_method","")} {h.get("url","")}'.strip()
    else:
        e["event_type"] = "anomaly"
    if not e["ts"] or not e["src_ip"]:
        return None
    return e


def norm_extra(r: dict):
    # already close to canonical; just fill the envelope
    e = _base()
    e.update({k: r.get(k) for k in (
        "ts", "service", "event_type", "src_ip", "src_port", "dst_port",
        "username", "password", "command") if r.get(k) is not None})
    e["sensor"] = "extra"
    e["raw"] = r
    if not e["ts"] or not e["src_ip"]:
        return None
    return e


def _svc_from_port(p):
    return {22: "ssh", 80: "http", 8080: "http", 3306: "mysql",
            21: "ftp", 6379: "redis"}.get(p, "tcp")


NORMALIZERS = {"cowrie": norm_cowrie, "suricata": norm_suricata, "extra": norm_extra}


# ───────────────────────── read checkpoints ─────────────────────────
# tail() used to seek to end-of-file on every start, so whatever a sensor wrote
# while the pipeline was down was skipped — silently, with nothing recording
# that a gap existed. Read positions are now persisted per file so a restart
# resumes where it left off.
#
# Delivery is at-least-once, not exactly-once: a checkpoint records what has
# been *read*, while the INSERT happens later in consumer(), so an unclean stop
# re-reads a bounded tail of the file. That is safe because event ids are
# derived from the record itself (see _event_id) and the insert is ON CONFLICT
# DO NOTHING, so a replayed line collides with itself instead of duplicating.

def _state_path(path: str) -> str:
    return os.path.join(STATE_DIR, os.path.basename(path) + ".offset")


def _load_checkpoint(path: str):
    """Return (inode, offset), or None when there is nothing usable on disk."""
    try:
        with open(_state_path(path)) as fh:
            st = json.load(fh)
        return int(st["inode"]), int(st["offset"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _save_checkpoint(path: str, inode: int, offset: int) -> None:
    """Persist the read position atomically. Never fatal: a lost checkpoint
    costs a replay, but a raising tail would cost live traffic."""
    target = _state_path(path)
    tmp = target + ".tmp"
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(tmp, "w") as fh:
            json.dump({"inode": inode, "offset": offset}, fh)
        os.replace(tmp, target)
    except OSError as ex:
        print(f"[pipeline] checkpoint write failed for "
              f"{os.path.basename(path)}: {ex}", flush=True)


def _probe_state_dir() -> None:
    """Say once, at startup, whether checkpoints can actually be persisted.

    _save_checkpoint deliberately fails soft — a lost checkpoint costs a replay,
    a raising tail costs live traffic — but that also means an unwritable
    STATE_DIR degrades into "silently skip to EOF on every restart", which is
    the exact bug the checkpoints were added to fix. The pipeline_state volume
    is seeded from the image with appuser's build-time uid, so an appuser uid
    that moves under an existing volume looks precisely like this.
    """
    probe = os.path.join(STATE_DIR, ".writable")
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(probe, "w") as fh:
            fh.write("ok")
        os.unlink(probe)
    except OSError as ex:
        print(f"[pipeline] STATE_DIR {STATE_DIR} is NOT writable ({ex}) — read "
              f"offsets cannot persist and every restart will skip to end of "
              f"file. Expected owner uid {os.getuid()} gid {os.getgid()}.",
              flush=True)


def _resume_position(path: str, fh, inode: int) -> None:
    """Seek to wherever this file should be read from, and say out loud when a
    gap is unavoidable rather than passing over it in silence.

    Two cases genuinely lose records and both are logged: no checkpoint at all
    (first ever start), and a checkpoint naming a file that has since rotated
    away — the previous file is gzipped by the rotation cron and not re-read.
    """
    name = os.path.basename(path)
    size = os.fstat(fh.fileno()).st_size
    checkpoint = _load_checkpoint(path)

    if checkpoint is None:
        fh.seek(0, os.SEEK_END)
        print(f"[pipeline] {name}: no checkpoint — starting at end of file; "
              f"records written before now are NOT ingested", flush=True)
        return

    saved_inode, offset = checkpoint
    if saved_inode != inode:
        fh.seek(0)
        print(f"[pipeline] {name}: rotated while down — resuming at the start "
              f"of the new file; records written past offset {offset} of the "
              f"previous file are NOT ingested", flush=True)
        return
    if offset > size:
        fh.seek(0)
        print(f"[pipeline] {name}: truncated while down (checkpoint {offset} > "
              f"size {size}) — resuming from the start", flush=True)
        return

    fh.seek(offset)
    if offset < size:
        print(f"[pipeline] {name}: resuming at offset {offset}, "
              f"{size - offset} bytes to catch up", flush=True)
    else:
        print(f"[pipeline] {name}: resuming at offset {offset}", flush=True)


# ───────────────────────── file tailer ─────────────────────────
async def tail(path: str, queue: asyncio.Queue, sensor: str, beat: str = None):
    """Keep one sensor's tail running for the life of the process.

    _tail_once() is the actual tailer; this wrapper exists because every way it
    can fail — a read error on the shared volume, a permission change under a
    rotated file, an ENOENT race the inner handlers miss — used to end that
    sensor's ingest for good while the process stayed up and healthy-looking.
    A dead tail is invisible: no crash, no restart, just one sensor that
    quietly stops producing events.
    """
    beat = beat or f"tail:{os.path.basename(path)}"
    attempt = 0
    while True:
        started = time.monotonic()
        try:
            await _tail_once(path, queue, sensor, beat)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            # A tail that ran for a long time before failing is a new problem,
            # not an escalating one — don't inherit the old backoff.
            if time.monotonic() - started > BACKOFF_RESET_S:
                attempt = 0
            attempt += 1
            waited = await retry.sleep(attempt)
            print(f"[pipeline] tail {os.path.basename(path)} failed "
                  f"({retry.oneline(ex)}) — reopened after {waited:.1f}s "
                  f"(attempt {attempt})", flush=True)


async def _tail_once(path: str, queue: asyncio.Queue, sensor: str, beat: str):
    """Follow a JSON-lines file, surviving rotation/truncation, resuming from
    the persisted offset so a restart does not skip what arrived while down.

    Opened in binary: fh.tell() is then a real byte offset that can be compared
    against st_size and handed back to seek(), which a text-mode handle does not
    guarantee. json.loads accepts bytes directly.
    """
    while not os.path.exists(path):
        heartbeat.beat(beat)
        await asyncio.sleep(2)
    fh = open(path, "rb")
    inode = os.fstat(fh.fileno()).st_ino
    unsaved = 0

    def _parse(raw):
        """Return the decoded record, or None when the line is not usable.
        ValueError covers both JSONDecodeError and the UnicodeDecodeError a
        partially-written or corrupt line can raise."""
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            return json.loads(stripped)
        except ValueError:
            return None

    try:
        _resume_position(path, fh, inode)
        # Persist the starting position immediately. Without this a tail that
        # never reads a line — the common case on a quiet sensor, and on every
        # first start, where we deliberately begin at EOF — would leave nothing
        # on disk, and the next start would take the "no checkpoint" branch and
        # skip ahead all over again.
        _save_checkpoint(path, inode, fh.tell())
        while True:
            line = fh.readline()
            if line:
                record = _parse(line)
                if record is not None:
                    await queue.put((sensor, record))
                heartbeat.beat(beat)
                unsaved += 1
                if unsaved >= CHECKPOINT_EVERY_LINES:
                    _save_checkpoint(path, inode, fh.tell())
                    unsaved = 0
                continue
            # Caught up. This is where the tail spends most of its life, so it
            # is both the cheapest and the most useful moment to record the
            # position — in steady state the replay window is a single line.
            if unsaved:
                _save_checkpoint(path, inode, fh.tell())
                unsaved = 0
            heartbeat.beat(beat)
            await asyncio.sleep(0.4)
            # detect rotation
            try:
                if os.stat(path).st_ino != inode:
                    # drain lines appended to the rotated-out file after our
                    # last read, so rotation doesn't drop events
                    while True:
                        line = fh.readline()
                        if not line:
                            break
                        record = _parse(line)
                        if record is not None:
                            await queue.put((sensor, record))
                    fh.close()
                    # the new file may not exist yet right after rotation —
                    # wait for it instead of crashing on a closed handle
                    while not os.path.exists(path):
                        heartbeat.beat(beat)
                        await asyncio.sleep(1)
                    fh = open(path, "rb")
                    inode = os.fstat(fh.fileno()).st_ino
                    # Record the new file at offset 0 immediately: a crash here
                    # must not send the next start back to a checkpoint that
                    # names the rotated-away inode.
                    unsaved = 0
                    _save_checkpoint(path, inode, fh.tell())
            except FileNotFoundError:
                await asyncio.sleep(1)
                if fh.closed:
                    while not os.path.exists(path):
                        heartbeat.beat(beat)
                        await asyncio.sleep(1)
                    fh = open(path, "rb")
                    inode = os.fstat(fh.fileno()).st_ino
                    unsaved = 0
                    _save_checkpoint(path, inode, fh.tell())
    finally:
        fh.close()


# ───────────────────────── writers ─────────────────────────
# Postgres cannot store NUL (U+0000) in either text or jsonb: a text column
# rejects the raw byte ("invalid byte sequence for encoding UTF8: 0x00") and
# jsonb rejects the escaped form json.dumps produces ("unsupported Unicode
# escape sequence"). A single NUL in a payload therefore fails both the events
# insert and its raw column.
#
# Attackers emit NULs routinely — overflow probes, protocol fuzzing, binary
# junk down a text port — and the insert error previously dropped the whole
# event: no events row, no ips upsert, no analytics stream, no enrich queue.
# That let a source stay invisible to scoring and enrichment just by including
# a NUL byte, so this is a (low-grade) evasion path, not only lost data.
#
# Replace rather than strip, so the payload keeps its shape and the tampering
# stays visible in the UI; the raw sensor log on disk retains the original
# bytes regardless.
NUL_REPLACEMENT = "�"


def _strip_nulls(value):
    """Recursively replace NUL characters in any string within value."""
    if isinstance(value, str):
        return value.replace("\x00", NUL_REPLACEMENT) if "\x00" in value else value
    if isinstance(value, dict):
        return {_strip_nulls(k): _strip_nulls(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_nulls(v) for v in value]
    return value


def _redact_password(pw):
    """Store a length hint instead of the actual password to preserve analytics
    value (password length distribution, blank-vs-set) without keeping PII."""
    if not pw:
        return None
    return f"[redacted:{len(pw)}chars]"


def _redact_raw(raw_dict):
    """Strip password fields from the raw sensor payload before storage."""
    if not isinstance(raw_dict, dict):
        return raw_dict
    scrubbed = dict(raw_dict)
    if "password" in scrubbed:
        scrubbed["password"] = _redact_password(scrubbed["password"])
    return scrubbed


def _event_id(sensor: str, record: dict) -> str:
    """Derive the event id from the record itself, so that re-reading a line
    after an unclean restart yields the same id and the INSERT below collapses
    the replay instead of writing the event a second time.

    The consequence is that two byte-identical records from one sensor become a
    single row. Real sensor output carries microsecond timestamps and session
    ids, so distinct events do not collide; an exact duplicate is the same event
    logged twice, which is what we want to drop anyway.
    """
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"),
                           default=str)
    return str(uuid.uuid5(_EVENT_NS, f"{sensor}\x1f{canonical}"))


class ItemError(Exception):
    """One record's failure, carrying the context needed to debug it. The
    underlying exception stays reachable as __cause__ so the retry policy can
    still tell a connection blip from a rejected payload."""

    def __init__(self, context: str, cause: BaseException):
        super().__init__(f"{context}: {retry.oneline(cause)}")


async def consumer(queue: asyncio.Queue, pool, r, beat: str = "consumer:0"):
    """Drain the queue forever. One record must never be able to end this loop:
    a normalizer that trips over an unexpected shape, a payload Postgres
    rejects, a Redis blip — all of them used to kill the task and, with it,
    a third of ingest, silently.

    Transient failures (connection refused, timeout, deadlock) are retried with
    backoff, because dropping the event would lose it for good — the tail has
    already moved past that line. Permanent failures (malformed record, schema
    violation) are logged once and skipped, because every retry reproduces them.
    """
    while True:
        try:
            sensor, record = await asyncio.wait_for(queue.get(),
                                                    timeout=IDLE_BEAT_S)
        except asyncio.TimeoutError:
            # An idle ingestor is a healthy ingestor; keep beating so the
            # watchdog doesn't mistake a quiet honeypot for a wedged loop.
            heartbeat.beat(beat)
            continue
        heartbeat.beat(beat)
        try:
            await _consume_one(sensor, record, pool, r, beat)
        finally:
            queue.task_done()


async def _consume_one(sensor: str, record: dict, pool, r, beat: str):
    for attempt in range(1, ITEM_MAX_ATTEMPTS + 1):
        try:
            await _handle(sensor, record, pool, r)
            return
        except Exception as ex:
            transient = retry.is_transient(ex)
            if not transient or attempt >= ITEM_MAX_ATTEMPTS:
                # Context, never the payload: it can carry credentials.
                print(f"[pipeline] dropped {sensor} record "
                      f"[{'transient' if transient else 'permanent'}, "
                      f"attempt {attempt}/{ITEM_MAX_ATTEMPTS}]: "
                      f"{retry.oneline(ex)}", flush=True)
                return
            waited = await retry.sleep(attempt)
            # Backing off is progress, not a stall.
            heartbeat.beat(beat)
            print(f"[pipeline] {sensor} record retry {attempt} after "
                  f"{waited:.1f}s: {retry.oneline(ex)}", flush=True)


async def _handle(sensor: str, record: dict, pool, r):
    """Normalize one record and write it to Postgres and the bus. Raises on
    failure; the caller decides whether that is worth a retry."""
    try:
        e = NORMALIZERS[sensor](record)
    except Exception as ex:
        # A normalizer only sees third-party sensor output, so an unexpected
        # shape is data, not a bug to crash on.
        raise ValueError(f"{sensor} normalizer rejected the record: "
                         f"{retry.oneline(ex)}") from None
    if not e:
        return
    # Replaces the random id the normalizer defaulted to; see _event_id.
    e["event_id"] = _event_id(sensor, record)
    # Before anything touches the DB or the bus, so every downstream
    # consumer sees the same storable payload.
    e = _strip_nulls(e)
    try:
        parsed_ip = ipaddress.ip_address(e["src_ip"])
    except (ValueError, TypeError):
        return
    if DROP_PRIVATE_SRC and _is_private_src(parsed_ip):
        return
    if e["src_ip"] in SELF_IPS:
        return
    ts = _parse_ts(e["ts"])
    stored_password = _redact_password(e["password"])
    stored_raw = json.dumps(_redact_raw(e["raw"]), default=str)
    try:
        async with pool.acquire() as con:
            # ON CONFLICT DO NOTHING makes ingest idempotent: after an
            # unclean stop the tail replays from its last checkpoint, and a
            # replayed line carries the same derived event_id as the row
            # already stored.
            stored = await con.fetchrow(
                """INSERT INTO events
                   (event_id, ts, sensor, service, event_type, src_ip, src_port,
                    dst_port, username, password, command, signature, severity,
                    session, raw)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                   ON CONFLICT DO NOTHING
                   RETURNING event_id""",
                uuid.UUID(e["event_id"]), ts, e["sensor"], e["service"],
                e["event_type"], e["src_ip"], e["src_port"], e["dst_port"],
                e["username"], stored_password, e["command"], e["signature"],
                e["severity"], e["session"], stored_raw,
            )
            if stored is None:
                # Already ingested. Skipping the rest matters as much as
                # skipping the insert: _upsert_ip increments event_count,
                # so replaying it would inflate per-IP counts and re-queue
                # enrichment for an IP that was already handled.
                return
            is_new = await _upsert_ip(con, e)
    except Exception as ex:
        # Re-raise with enough context to identify the offending stream, but
        # never the payload itself (it may carry credentials). The original is
        # kept as __cause__, which is what retry.is_transient classifies on.
        raise ItemError(f"db error [{e.get('sensor')} {e.get('src_ip')} "
                        f"{e.get('event_type')}]", ex) from ex
    # publish to the bus
    payload = {k: ("" if v is None else str(v)) for k, v in e.items() if k != "raw"}
    await r.xadd(EVENTS_STREAM, payload, maxlen=200000, approximate=True)
    if is_new:
        await r.xadd(ENRICH_STREAM, {"src_ip": e["src_ip"]}, maxlen=50000,
                     approximate=True)


# Cap the distinct-value arrays on the hot ips row. Past this many distinct
# ports/services an IP is already unambiguously a scanner; further growth adds no
# analytic value but turns every event from that IP into an O(n) membership scan
# plus a full-row (eventually TOASTed) rewrite. A hyperactive scanner reached 798
# ports before this cap existed.
PORTS_HIT_CAP = 128
SERVICES_HIT_CAP = 32


async def _upsert_ip(con, e) -> bool:
    # dst_port may be NULL (most cowrie events don't carry it) — record no port
    # rather than a fabricated one
    row = await con.fetchrow(
        """INSERT INTO ips (src_ip, services_hit, ports_hit, event_count)
           VALUES ($1, ARRAY[$2]::text[],
                   CASE WHEN $3::int IS NULL THEN '{}'::int[] ELSE ARRAY[$3]::int[] END, 1)
           ON CONFLICT (src_ip) DO UPDATE SET
             last_seen = now(),
             event_count = ips.event_count + 1,
             services_hit = CASE
                 WHEN $2 = ANY(ips.services_hit)
                   OR cardinality(ips.services_hit) >= $4 THEN ips.services_hit
                 ELSE ips.services_hit || $2::text END,
             ports_hit = CASE
                 WHEN $3::int IS NULL OR $3 = ANY(ips.ports_hit)
                   OR cardinality(ips.ports_hit) >= $5 THEN ips.ports_hit
                 ELSE ips.ports_hit || $3::int END
           RETURNING (xmax = 0) AS inserted""",
        e["src_ip"], e["service"] or "tcp", e["dst_port"],
        SERVICES_HIT_CAP, PORTS_HIT_CAP,
    )
    return bool(row and row["inserted"])


def _parse_ts(s):
    if not s:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _db_creds():
    svc_pw = os.environ.get("SVC_DB_PASSWORD", "")
    if svc_pw:
        return os.environ.get("SVC_DB_USER", os.environ["PG_USER"]), svc_pw
    return os.environ["PG_USER"], os.environ["PG_PASSWORD"]


async def _connect_pool():
    """Wait for Postgres rather than dying on it. depends_on makes this rare at
    boot, but a database restart mid-life would otherwise take the ingestor
    with it and leave the restart policy to race the same window."""
    user, password = _db_creds()
    attempt = 0
    while True:
        try:
            return await asyncpg.create_pool(
                host=os.environ["PG_HOST"],
                port=int(os.environ["PG_PORT"]),
                database=os.environ["PG_DB"],
                user=user,
                password=password,
                min_size=2, max_size=8,
                # Without this a single wedged query holds its connection for
                # ever; the pool then drains and every acquire() blocks behind
                # it, which is a live process that has quietly stopped working.
                command_timeout=PG_COMMAND_TIMEOUT_S,
                timeout=PG_CONNECT_TIMEOUT_S,
            )
        except Exception as ex:
            attempt += 1
            waited = await retry.sleep(attempt)
            print(f"[pipeline] postgres unavailable ({retry.oneline(ex)}) — "
                  f"retry {attempt} in {waited:.1f}s", flush=True)


def _redis_client():
    """Redis with socket timeouts. The default client has none: against a peer
    that is gone but whose TCP connection was never torn down (a container
    restart, a NAT table expiry), a blocking XADD or XREAD waits for ever —
    process alive, no CPU, no logs, no restart. That is the classic hang here,
    and no amount of try/except catches a call that never returns."""
    return redis.from_url(
        os.environ["REDIS_URL"], decode_responses=True,
        socket_timeout=REDIS_SOCKET_TIMEOUT_S,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_S,
        socket_keepalive=True,
        health_check_interval=30,
        retry_on_timeout=True,
    )


async def main():
    heartbeat.start(HEARTBEATS)
    _probe_state_dir()
    pool = await _connect_pool()
    r = _redis_client()
    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    tails = [asyncio.create_task(tail(os.path.join(LOG_DIR, f), queue, s,
                                      f"tail:{f}"))
             for f, s in FILES.items()]
    consumers = [asyncio.create_task(consumer(queue, pool, r, f"consumer:{i}"))
                 for i in range(CONSUMERS)]
    watchdog = asyncio.create_task(heartbeat.watchdog(HEARTBEATS))
    print("[pipeline] ingesting:", list(FILES),
          "| drop_private_src:", DROP_PRIVATE_SRC,
          "| queue_max:", QUEUE_MAX, "| consumers:", CONSUMERS, flush=True)

    stopper = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait([*tails, *consumers, watchdog, stopper],
                                 return_when=asyncio.FIRST_COMPLETED)
    if stopper not in done:
        for task in done:
            if not task.cancelled() and task.exception():
                print(f"[pipeline] loop exited unexpectedly: "
                      f"{retry.oneline(task.exception())}", flush=True)

    # Shut down in dependency order so in-flight work is not abandoned: stop
    # reading first, let the consumers finish what is already queued, and only
    # then tear down the connections they were writing through. Records still
    # queued past the drain window are not lost — no checkpoint has advanced
    # past them, so the next start replays from the last persisted offset and
    # ON CONFLICT DO NOTHING collapses whatever did land.
    print("[pipeline] stopping — draining queue", flush=True)
    for task in (*tails, watchdog, stopper):
        task.cancel()
    await asyncio.gather(*tails, watchdog, stopper, return_exceptions=True)
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(queue.join(), timeout=SHUTDOWN_DRAIN_S)
    for task in consumers:
        task.cancel()
    await asyncio.gather(*consumers, return_exceptions=True)
    await pool.close()
    await r.aclose()
    print("[pipeline] stopped", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
