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
import ipaddress
import json
import os
import uuid
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as redis

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
async def tail(path: str, queue: asyncio.Queue, sensor: str):
    """Follow a JSON-lines file, surviving rotation/truncation, resuming from
    the persisted offset so a restart does not skip what arrived while down.

    Opened in binary: fh.tell() is then a real byte offset that can be compared
    against st_size and handed back to seek(), which a text-mode handle does not
    guarantee. json.loads accepts bytes directly.
    """
    while not os.path.exists(path):
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


async def consumer(queue: asyncio.Queue, pool, r):
    while True:
        sensor, record = await queue.get()
        e = NORMALIZERS[sensor](record)
        if not e:
            continue
        # Replaces the random id the normalizer defaulted to; see _event_id.
        e["event_id"] = _event_id(sensor, record)
        # Before anything touches the DB or the bus, so every downstream
        # consumer sees the same storable payload.
        e = _strip_nulls(e)
        try:
            parsed_ip = ipaddress.ip_address(e["src_ip"])
        except (ValueError, TypeError):
            continue
        if DROP_PRIVATE_SRC and _is_private_src(parsed_ip):
            continue
        if e["src_ip"] in SELF_IPS:
            continue
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
                    continue
                is_new = await _upsert_ip(con, e)
        except Exception as ex:
            # Include enough context to identify the offending stream without
            # logging the payload itself (it may carry credentials).
            print(f"[pipeline] db error [{e.get('sensor')} {e.get('src_ip')} "
                  f"{e.get('event_type')}]: "
                  f"{str(ex).replace(chr(10), ' ').replace(chr(13), '')}", flush=True)
            continue
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


async def main():
    user, password = _db_creds()
    pool = await asyncpg.create_pool(
        host=os.environ["PG_HOST"],
        port=int(os.environ["PG_PORT"]),
        database=os.environ["PG_DB"],
        user=user,
        password=password,
        min_size=2, max_size=8,
    )
    r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
    tasks = [asyncio.create_task(tail(os.path.join(LOG_DIR, f), queue, s))
             for f, s in FILES.items()]
    tasks += [asyncio.create_task(consumer(queue, pool, r)) for _ in range(3)]
    print("[pipeline] ingesting:", list(FILES),
          "| drop_private_src:", DROP_PRIVATE_SRC, flush=True)
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
