#!/usr/bin/env python3
"""
Enrichment worker. Consumes the enrich:queue stream (new IPs from the pipeline),
calls the active provider, and upserts ip_enrichment. Provider is chosen at runtime
from settings -> fully swappable without touching anything else.
"""
import asyncio
import ipaddress
import json
import os

import asyncpg
import redis.asyncio as redis

import providers  # noqa: F401  (registers the provider classes)
from base import get_provider

ENRICH_STREAM = "enrich:queue"
GROUP = "enrichers"
CONSUMER = os.environ.get("HOSTNAME", "enricher-1")
CACHE_TTL = 3600  # don't re-enrich the same IP within an hour

# Re-enrichment: the pipeline only queues an IP the first time it is seen, so
# without this loop ip_enrichment rows would stay frozen forever — including
# rows written while API keys were missing or a provider was down.
REFRESH_INTERVAL_S = 3600
REFRESH_BATCH = 200        # cap per hour to respect provider quotas (VT: 500/day)
REFRESH_STALE = "7 days"   # normal refresh age for still-active IPs
REFRESH_RETRY = "6 hours"  # retry age for rows that never got a verdict


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
    """Hourly: re-queue enrichment for IPs still active in the last 24h whose
    intel is stale, or which never got a verdict (unknown reputation)."""
    while True:
        try:
            async with pool.acquire() as con:
                rows = await con.fetch(
                    f"""SELECT host(e.src_ip) AS ip FROM ip_enrichment e
                        JOIN ips i ON i.src_ip = e.src_ip
                        WHERE i.last_seen > now() - interval '24 hours'
                          AND (e.updated_at < now() - interval '{REFRESH_STALE}'
                               OR (e.reputation = 'unknown'
                                   AND e.updated_at < now() - interval '{REFRESH_RETRY}'))
                        ORDER BY e.updated_at ASC LIMIT $1""", REFRESH_BATCH)
            for row in rows:
                await r.xadd(ENRICH_STREAM, {"src_ip": row["ip"], "force": "1"},
                             maxlen=50000, approximate=True)
            if rows:
                print(f"[enrichment] re-queued {len(rows)} stale IPs", flush=True)
        except Exception as ex:
            safe = str(ex).replace("\n", " ").replace("\r", "")
            print(f"[enrichment] refresh loop: {safe}", flush=True)
        await asyncio.sleep(REFRESH_INTERVAL_S)


async def consume(pool, r, provider):
    while True:
        resp = await r.xreadgroup(GROUP, CONSUMER, {ENRICH_STREAM: ">"},
                                  count=20, block=5000)
        if not resp:
            continue
        for _stream, messages in resp:
            for msg_id, fields in messages:
                ip = fields.get("src_ip")
                force = fields.get("force") == "1"
                try:
                    if ip:
                        ipaddress.ip_address(ip)
                    if ip and (force or not await r.get(f"enr:seen:{ip}")):
                        enr = await provider.enrich(ip)
                        await upsert(pool, enr)
                        # feed threat hint back to the IP record
                        if enr.is_known_attacker:
                            async with pool.acquire() as con:
                                await con.execute(
                                    "UPDATE ips SET threat_score = GREATEST(threat_score, $2) "
                                    "WHERE src_ip=$1", ip, 60.0)
                        await r.set(f"enr:seen:{ip}", "1", ex=CACHE_TTL)
                except Exception as ex:
                    safe_ip = str(ip).replace("\n", "").replace("\r", "")
                    safe_err = str(ex).replace("\n", " ").replace("\r", "")
                    print(f"[enrichment] {safe_ip}: {safe_err}", flush=True)
                finally:
                    await r.xack(ENRICH_STREAM, GROUP, msg_id)


async def main():
    user, password = _db_creds()
    pool = await asyncpg.create_pool(
        host=os.environ["PG_HOST"],
        port=int(os.environ["PG_PORT"]),
        database=os.environ["PG_DB"],
        user=user,
        password=password,
        min_size=1, max_size=4,
    )
    r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    await ensure_group(r)

    settings = await load_settings(pool)
    provider_name = (settings.get("enrichment_provider", "").strip('"')
                     or os.environ.get("ENRICHMENT_PROVIDER", "crowdsec"))
    provider = get_provider(provider_name, settings)
    print(f"[enrichment] provider = {provider.name}", flush=True)

    await asyncio.gather(consume(pool, r, provider), refresh_loop(pool, r))


if __name__ == "__main__":
    asyncio.run(main())
