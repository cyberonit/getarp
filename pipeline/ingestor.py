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
import json
import os
import uuid
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as redis

LOG_DIR = os.environ.get("LOG_DIR", "/data/logs")
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
    e["service"] = "telnet" if "telnet" in str(r.get("protocol", "")).lower() else "ssh"
    e["event_type"] = COWRIE_MAP.get(eventid, ("event", None))[0]
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
    return {22: "ssh", 23: "telnet", 80: "http", 8080: "http", 3306: "mysql",
            21: "ftp", 6379: "redis"}.get(p, "tcp")


NORMALIZERS = {"cowrie": norm_cowrie, "suricata": norm_suricata, "extra": norm_extra}


# ───────────────────────── file tailer ─────────────────────────
async def tail(path: str, queue: asyncio.Queue, sensor: str):
    """Follow a JSON-lines file, surviving rotation/truncation."""
    while not os.path.exists(path):
        await asyncio.sleep(2)
    inode = os.stat(path).st_ino
    fh = open(path, "r")
    try:
        fh.seek(0, os.SEEK_END)  # start at tail; we want live traffic
        while True:
            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        await queue.put((sensor, json.loads(line)))
                    except json.JSONDecodeError:
                        pass
                continue
            await asyncio.sleep(0.4)
            # detect rotation
            try:
                if os.stat(path).st_ino != inode:
                    fh.close()
                    fh = open(path, "r")
                    inode = os.fstat(fh.fileno()).st_ino
            except FileNotFoundError:
                await asyncio.sleep(1)
    finally:
        fh.close()


# ───────────────────────── writers ─────────────────────────
async def consumer(queue: asyncio.Queue, pool, r):
    while True:
        sensor, record = await queue.get()
        e = NORMALIZERS[sensor](record)
        if not e:
            continue
        ts = _parse_ts(e["ts"])
        try:
            async with pool.acquire() as con:
                await con.execute(
                    """INSERT INTO events
                       (event_id, ts, sensor, service, event_type, src_ip, src_port,
                        dst_port, username, password, command, signature, severity,
                        session, raw)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""",
                    uuid.UUID(e["event_id"]), ts, e["sensor"], e["service"],
                    e["event_type"], e["src_ip"], e["src_port"], e["dst_port"],
                    e["username"], e["password"], e["command"], e["signature"],
                    e["severity"], e["session"], json.dumps(e["raw"], default=str),
                )
                is_new = await _upsert_ip(con, e)
        except Exception as ex:
            print(f"[pipeline] db error: {ex}", flush=True)
            continue
        # publish to the bus
        payload = {k: ("" if v is None else str(v)) for k, v in e.items() if k != "raw"}
        await r.xadd(EVENTS_STREAM, payload, maxlen=200000, approximate=True)
        if is_new:
            await r.xadd(ENRICH_STREAM, {"src_ip": e["src_ip"]}, maxlen=50000,
                         approximate=True)


async def _upsert_ip(con, e) -> bool:
    row = await con.fetchrow(
        """INSERT INTO ips (src_ip, services_hit, ports_hit, event_count)
           VALUES ($1, ARRAY[$2]::text[], ARRAY[$3]::int[], 1)
           ON CONFLICT (src_ip) DO UPDATE SET
             last_seen = now(),
             event_count = ips.event_count + 1,
             services_hit = CASE WHEN $2 = ANY(ips.services_hit) THEN ips.services_hit
                                  ELSE ips.services_hit || $2::text END,
             ports_hit = CASE WHEN $3 = ANY(ips.ports_hit) THEN ips.ports_hit
                              ELSE ips.ports_hit || $3::int END
           RETURNING (xmax = 0) AS inserted""",
        e["src_ip"], e["service"] or "tcp", e["dst_port"] or 0,
    )
    return bool(row and row["inserted"])


def _parse_ts(s):
    if not s:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


async def main():
    pool = await asyncpg.create_pool(
        host=os.environ["PG_HOST"],
        port=int(os.environ["PG_PORT"]),
        database=os.environ["PG_DB"],
        user=os.environ["PG_USER"],
        password=os.environ["PG_PASSWORD"],
        min_size=2, max_size=8,
    )
    r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
    tasks = [asyncio.create_task(tail(os.path.join(LOG_DIR, f), queue, s))
             for f, s in FILES.items()]
    tasks += [asyncio.create_task(consumer(queue, pool, r)) for _ in range(3)]
    print("[pipeline] ingesting:", list(FILES), flush=True)
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
