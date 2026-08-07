#!/usr/bin/env python3
"""
Enrichment worker. Consumes the enrich:queue stream (new IPs from the pipeline),
calls the active provider, and upserts ip_enrichment. Provider is chosen at runtime
from settings -> fully swappable without touching anything else.
"""
import asyncio
import contextlib
import ipaddress
import json
import os
import signal

import asyncpg
import redis.asyncio as redis

import heartbeat
import providers  # noqa: F401  (registers the provider classes)
import retry
from base import get_provider

ENRICH_STREAM = "enrich:queue"
GROUP = "enrichers"
CONSUMER = os.environ.get("HOSTNAME", "enricher-1")

# Durable cache: a fresh ip_enrichment row short-circuits re-enrichment, so
# restarts never re-spend Tier-2 quota (the old 1h Redis marker didn't survive
# them). force=1 (refresh loop) bypasses it.
CACHE_TTL_DAYS = int(os.environ.get("ENRICHMENT_CACHE_TTL_DAYS", "14"))

# Re-enrichment: the pipeline only queues an IP the first time it is seen, so
# without this loop ip_enrichment rows would stay frozen forever — including
# rows written while API keys were missing or a provider was down.
REFRESH_INTERVAL_S = 3600
REFRESH_BATCH = 200        # cap per hour to respect provider quotas (VT: 500/day)
REFRESH_STALE = f"{CACHE_TTL_DAYS} days"  # normal refresh age for still-active IPs
REFRESH_RETRY = "6 hours"  # retry age for rows that never got a verdict

# Tier-1 feed refresh cadence (see feeds.py)
FEED_REFRESH_S = int(float(os.environ.get("FEED_REFRESH_HOURS", "3")) * 3600)

# ───────────────────────── runtime tuning ─────────────────────────
# How many times one IP is re-queued after a transient failure before it is
# given up on. Re-queueing rather than leaving the message unacked is
# deliberate: an unacked entry sits in the group's pending list, and nothing
# would ever come back for it.
MAX_ATTEMPTS = int(os.environ.get("ENRICH_MAX_ATTEMPTS") or 5)
# Messages left pending by a worker that died mid-flight are reclaimed after
# this long. Without it, whatever was in flight at the moment of a restart is
# lost — silently, since the stream itself looks empty afterwards.
RECLAIM_IDLE_MS = int(float(os.environ.get("ENRICH_RECLAIM_IDLE_S") or 300) * 1000)
RECLAIM_INTERVAL_S = float(os.environ.get("ENRICH_RECLAIM_INTERVAL_S") or 60)

REDIS_SOCKET_TIMEOUT_S = float(os.environ.get("REDIS_SOCKET_TIMEOUT_S") or 30.0)
REDIS_CONNECT_TIMEOUT_S = float(os.environ.get("REDIS_CONNECT_TIMEOUT_S") or 10.0)
PG_COMMAND_TIMEOUT_S = float(os.environ.get("PG_COMMAND_TIMEOUT_S") or 30.0)
PG_CONNECT_TIMEOUT_S = float(os.environ.get("PG_CONNECT_TIMEOUT_S") or 10.0)

# Liveness thresholds, one per concurrent loop — see heartbeat.py. consume's
# threshold has to clear a full Tier-2 chain (several provider calls, each with
# its own timeout) plus a backoff cycle; the two periodic loops are given twice
# their own interval, since anything less would flag a slow-but-working feed
# download as a hang.
HEARTBEATS = {
    "consume": heartbeat.env_seconds("ENRICH_CONSUME_STALE_S", 300),
    "refresh": heartbeat.env_seconds("ENRICH_REFRESH_STALE_S",
                                     REFRESH_INTERVAL_S * 2),
    "feeds": heartbeat.env_seconds("ENRICH_FEEDS_STALE_S", FEED_REFRESH_S * 2),
}


async def ensure_group(r):
    try:
        await r.xgroup_create(ENRICH_STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


async def upsert(pool, enr):
    d = enr.as_db()
    async with pool.acquire() as con:
        await con.execute(
            """INSERT INTO ip_enrichment
               (src_ip, provider, country, asn, org, reputation, confidence,
                categories, is_known_attacker, raw, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
               ON CONFLICT (src_ip) DO UPDATE SET
                 provider=$2, country=$3, asn=$4, org=$5, reputation=$6,
                 confidence=$7, categories=$8, is_known_attacker=$9, raw=$10,
                 updated_at=now()""",
            d["src_ip"], d["provider"], d["country"], d["asn"], d["org"],
            d["reputation"], d["confidence"], d["categories"],
            d["is_known_attacker"], json.dumps(d["raw"], default=str),
        )


async def load_settings(pool) -> dict:
    s = dict(os.environ)
    async with pool.acquire() as con:
        rows = await con.fetch("SELECT key, value FROM settings")
    for row in rows:
        s[row["key"]] = row["value"]
        s[row["key"].upper()] = row["value"]
    return s


def _db_creds():
    svc_pw = os.environ.get("SVC_DB_PASSWORD", "")
    if svc_pw:
        return os.environ.get("SVC_DB_USER", os.environ["PG_USER"]), svc_pw
    return os.environ["PG_USER"], os.environ["PG_PASSWORD"]


async def refresh_loop(pool, r):
    """Hourly: re-queue enrichment for IPs with no enrichment row at all (missed
    while the worker was down or misconfigured), IPs still active in the last
    24h whose intel is stale, and IPs whose Tier-2 lookup was deferred by a
    quota gate — the last group is retried regardless of recency, since a
    one-off scanner that hit during a quota-exhausted window would otherwise
    never get a verdict (see enrichment/tests/test_quota_resilience.py)."""
    while True:
        heartbeat.beat("refresh")
        try:
            async with pool.acquire() as con:
                rows = await con.fetch(
                    f"""SELECT host(i.src_ip) AS ip
                        FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip = i.src_ip
                        WHERE e.src_ip IS NULL
                           OR (i.last_seen > now() - interval '24 hours'
                               AND e.updated_at < now() - interval '{REFRESH_STALE}')
                           OR (e.reputation = 'unknown'
                               AND jsonb_array_length(e.raw->'tiered'->'tier2_deferred') > 0
                               AND e.updated_at < now() - interval '{REFRESH_RETRY}')
                        ORDER BY e.updated_at ASC NULLS FIRST LIMIT $1""", REFRESH_BATCH)
            for row in rows:
                await r.xadd(ENRICH_STREAM, {"src_ip": row["ip"], "force": "1"},
                             maxlen=50000, approximate=True)
            if rows:
                print(f"[enrichment] re-queued {len(rows)} stale IPs", flush=True)
        except Exception as ex:
            safe = str(ex).replace("\n", " ").replace("\r", "")
            print(f"[enrichment] refresh loop: {safe}", flush=True)
        await asyncio.sleep(REFRESH_INTERVAL_S)


async def is_fresh(pool, ip: str) -> bool:
    """True when the durable Postgres cache still covers this IP."""
    async with pool.acquire() as con:
        return bool(await con.fetchval(
            "SELECT updated_at > now() - make_interval(days => $2) "
            "FROM ip_enrichment WHERE src_ip=$1", ip, CACHE_TTL_DAYS))


async def feed_refresh_loop(pool, provider):
    """Load cached Tier-1 feeds at startup, then refresh each on an interval.
    Each feed fails independently — refresh() logs and keeps its last copy."""
    feeds = getattr(provider, "feed_providers", [])
    if not feeds:
        # A provider with no Tier-1 feeds still has to beat: the watchdog
        # cannot tell "nothing to refresh" from "wedged", and would restart the
        # worker every ENRICH_FEEDS_STALE_S if this simply returned.
        while True:
            heartbeat.beat("feeds")
            await asyncio.sleep(60)
    for f in feeds:
        heartbeat.beat("feeds")
        try:
            await f.load(pool)
        except Exception as ex:
            print(f"[feeds] {f.name} load failed: {retry.oneline(ex)}", flush=True)
    while True:
        for f in feeds:
            # Per feed, not per cycle: a GeoLite2 download can take minutes,
            # and a cycle-level beat would go stale part way through a refresh
            # that is working perfectly well.
            heartbeat.beat("feeds")
            try:
                await f.refresh(pool)
            except Exception as ex:
                print(f"[feeds] {f.name} refresh failed: {retry.oneline(ex)}",
                      flush=True)
        heartbeat.beat("feeds")
        await asyncio.sleep(FEED_REFRESH_S)


async def enrich_one(pool, provider, ip: str, force: bool):
    """Enrich one IP. Raises on failure — handle_message decides from the
    exception whether that is worth another attempt."""
    if not ip:
        raise ValueError("stream message carries no src_ip")
    ipaddress.ip_address(ip)        # ValueError: malformed, never retryable
    if not force and await is_fresh(pool, ip):
        return
    enr = await provider.enrich(ip)
    await upsert(pool, enr)
    # feed threat hint back to the IP record
    if enr.is_known_attacker:
        async with pool.acquire() as con:
            await con.execute(
                "UPDATE ips SET threat_score = GREATEST(threat_score, $2) "
                "WHERE src_ip=$1", ip, 60.0)


async def handle_message(pool, r, provider, msg_id, fields):
    """Process one stream entry and ACK it, whatever happens.

    A provider timeout or a Postgres blip must not cost the IP its enrichment:
    those are re-queued, up to MAX_ATTEMPTS, and only then given up on. The IP
    is handed back to the stream rather than left unacked, because an unacked
    entry just accumulates in the group's pending list where nothing looks for
    it — the reclaim loop exists for entries a *dead* worker left behind, not
    as a retry channel.

    Permanent failures (a malformed address, a payload Postgres rejects) are
    logged once and dropped: every retry reproduces them exactly.
    """
    ip = fields.get("src_ip")
    attempt = int(fields.get("attempt") or 0)
    safe_ip = str(ip).replace("\n", "").replace("\r", "")
    try:
        await enrich_one(pool, provider, ip, fields.get("force") == "1")
    except Exception as ex:
        transient = retry.is_transient(ex)
        if transient and attempt + 1 < MAX_ATTEMPTS:
            waited = await retry.sleep(attempt + 1)
            heartbeat.beat("consume")
            with contextlib.suppress(Exception):
                await r.xadd(ENRICH_STREAM,
                             {"src_ip": str(ip), "force": fields.get("force", "0"),
                              "attempt": str(attempt + 1)},
                             maxlen=50000, approximate=True)
            print(f"[enrichment] {safe_ip}: {retry.oneline(ex)} — re-queued "
                  f"after {waited:.1f}s (attempt {attempt + 1}/{MAX_ATTEMPTS})",
                  flush=True)
        else:
            reason = "gave up" if transient else "permanent"
            print(f"[enrichment] {safe_ip}: {retry.oneline(ex)} [{reason}]",
                  flush=True)
    finally:
        # Never fatal: a failed ACK leaves the entry pending, which the reclaim
        # loop is there to pick up.
        try:
            await r.xack(ENRICH_STREAM, GROUP, msg_id)
        except Exception as ex:
            print(f"[enrichment] ack failed for {msg_id}: {retry.oneline(ex)}",
                  flush=True)


async def consume(pool, r, provider, stop=None):
    """Read the enrich queue forever.

    The outer try is the difference between a worker that survives a Redis
    restart and one that exits on it: xreadgroup raising used to end this
    coroutine, and asyncio.gather then brought the whole process down.
    """
    attempt = 0
    while True:
        if stop is not None and stop.is_set():
            return
        try:
            resp = await r.xreadgroup(GROUP, CONSUMER, {ENRICH_STREAM: ">"},
                                      count=20, block=5000)
        except Exception as ex:
            attempt += 1
            heartbeat.beat("consume")
            waited = await retry.sleep(attempt)
            print(f"[enrichment] stream read failed ({retry.oneline(ex)}) — "
                  f"reconnecting, attempt {attempt} in {waited:.1f}s", flush=True)
            # The group can vanish with the stream (a flushed or evicted Redis),
            # in which case every subsequent read fails until it is recreated.
            with contextlib.suppress(Exception):
                await ensure_group(r)
            continue
        attempt = 0
        heartbeat.beat("consume")
        if not resp:
            continue
        for _stream, messages in resp:
            for msg_id, fields in messages:
                await handle_message(pool, r, provider, msg_id, fields)
                heartbeat.beat("consume")
                if stop is not None and stop.is_set():
                    return


async def reclaim_loop(pool, r, provider):
    """Re-deliver entries a previous worker took but never ACKed.

    Anything in flight when a worker is killed — by the watchdog, by an OOM, by
    a deploy — stays in the group's pending list for ever otherwise: XREADGROUP
    with '>' only ever returns entries nobody has seen, so those IPs are lost
    while the stream itself looks empty.
    """
    cursor = "0-0"
    while True:
        await asyncio.sleep(RECLAIM_INTERVAL_S)
        try:
            resp = await r.xautoclaim(ENRICH_STREAM, GROUP, CONSUMER,
                                      min_idle_time=RECLAIM_IDLE_MS,
                                      start_id=cursor, count=50)
            cursor, messages = resp[0], resp[1]
            if not messages:
                continue
            print(f"[enrichment] reclaimed {len(messages)} abandoned message(s)",
                  flush=True)
            for msg_id, fields in messages:
                await handle_message(pool, r, provider, msg_id, fields)
                heartbeat.beat("consume")
        except Exception as ex:
            cursor = "0-0"
            print(f"[enrichment] reclaim failed: {retry.oneline(ex)}", flush=True)


async def _connect_pool():
    """Wait for Postgres rather than dying on it — a database restart must not
    take the worker with it and leave the restart policy racing the same
    window on the way back up."""
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
                min_size=1, max_size=4,
                # Without this one wedged query holds its connection for ever;
                # with a pool of 4 that is a worker which looks alive and has
                # quietly stopped enriching anything.
                command_timeout=PG_COMMAND_TIMEOUT_S,
                timeout=PG_CONNECT_TIMEOUT_S,
            )
        except Exception as ex:
            attempt += 1
            waited = await retry.sleep(attempt)
            print(f"[enrichment] postgres unavailable ({retry.oneline(ex)}) — "
                  f"retry {attempt} in {waited:.1f}s", flush=True)


def _redis_client():
    """Redis with socket timeouts. The default client has none: against a peer
    that is gone but whose TCP connection was never torn down, the blocking
    XREADGROUP below waits for ever — process alive, no CPU, no logs, no
    restart. try/except cannot catch a call that never returns."""
    return redis.from_url(
        os.environ["REDIS_URL"], decode_responses=True,
        # Must exceed the 5s XREADGROUP block below, or every idle read would
        # time out as an error.
        socket_timeout=REDIS_SOCKET_TIMEOUT_S,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_S,
        socket_keepalive=True,
        health_check_interval=30,
        retry_on_timeout=True,
    )


async def main():
    heartbeat.start(HEARTBEATS)
    pool = await _connect_pool()
    r = _redis_client()
    await ensure_group(r)

    settings = await load_settings(pool)
    provider_name = (settings.get("enrichment_provider", "").strip('"')
                     or os.environ.get("ENRICHMENT_PROVIDER", "crowdsec"))
    provider = get_provider(provider_name, settings)
    if hasattr(provider, "bind"):
        provider.bind(pool)
    print(f"[enrichment] provider = {provider.name}", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    consumer = asyncio.create_task(consume(pool, r, provider, stop))
    others = [asyncio.create_task(refresh_loop(pool, r)),
              asyncio.create_task(feed_refresh_loop(pool, provider)),
              asyncio.create_task(reclaim_loop(pool, r, provider)),
              asyncio.create_task(heartbeat.watchdog(HEARTBEATS))]

    stopper = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait([consumer, *others, stopper],
                                 return_when=asyncio.FIRST_COMPLETED)
    if stopper not in done:
        for task in done:
            if not task.cancelled() and task.exception():
                print(f"[enrichment] loop exited unexpectedly: "
                      f"{retry.oneline(task.exception())}", flush=True)

    # consume() checks `stop` between messages, so give it a moment to finish
    # the IP it is on: an interrupted enrichment would be re-queued and re-spend
    # Tier-2 quota that has already been paid for.
    print("[enrichment] stopping — finishing in-flight lookup", flush=True)
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(consumer), timeout=30)
    for task in (consumer, *others, stopper):
        task.cancel()
    await asyncio.gather(consumer, *others, stopper, return_exceptions=True)
    await pool.close()
    await r.aclose()
    print("[enrichment] stopped", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
