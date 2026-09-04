"""Repoint existing ip_enrichment geo at whichever feed now has precedence.

Written for the ipinfo-lite feed (985933d), which takes the country ahead of
geolite. Adding that feed only changes rows as they are re-enriched, so without
this the map takes ENRICHMENT_CACHE_TTL_DAYS to converge. Applied on this host
2026-09-04: 8 280 of 36 156 rows (2 556 countries changed, 825 gained).

Geo ONLY. Reputation, confidence, categories, is_known_attacker and updated_at
are never touched. That is the point of doing it here rather than by re-queueing
the IPs with force=1: force bypasses the cache and re-runs the whole tiered
flow, so on this dataset it would put ~33 000 IPs through the Tier-2 activity
gate, exhaust GreyNoise's weekly and AbuseIPDB's daily quota within minutes, and
then overwrite real verdicts with the "unknown" that a quota-exhausted stub
merges to. This reads the two local .mmdb files and makes no API calls at all.

Leaving updated_at alone matters too: bumping it would mark 8 000 rows fresh and
suppress their next legitimate re-enrichment for the whole cache window.

Usage (dry run reports, writes nothing):

    docker compose run --rm --no-deps --user root \
      -v "$PWD/maintenance:/work:ro" --entrypoint python enrichment \
      /work/backfill-geo.py

    ... same with -e APPLY=1 to write. Snapshot the columns first:
    CREATE TABLE ip_enrichment_geo_backup AS
      SELECT src_ip, country, asn, org FROM ip_enrichment;
"""
import asyncio
import datetime
import os

import asyncpg
import maxminddb

APPLY = os.environ.get("APPLY") == "1"
NOW = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")

GEOIP_DIR = os.environ.get("GEOIP_DIR", "/geoip")


def _open(name):
    """Missing database is not fatal — either source alone still backfills."""
    path = os.path.join(GEOIP_DIR, name)
    try:
        return maxminddb.open_database(path)
    except Exception as ex:
        print(f"[backfill] {name} unavailable: {ex}", flush=True)
        return None


ipi = _open("ipinfo-country_asn.mmdb")
gl_city = _open("GeoLite2-City.mmdb")
gl_asn = _open("GeoLite2-ASN.mmdb")
if not (ipi or gl_city or gl_asn):
    raise SystemExit("[backfill] no geo databases available, nothing to do")


def geo(ip):
    """Same precedence the tiered provider now uses: ipinfo-lite, then geolite."""
    r = (ipi.get(ip) or {}) if ipi else {}
    asn = str(r.get("asn") or "")
    asn = asn[2:] if asn.upper().startswith("AS") else asn
    country, org = r.get("country"), r.get("as_name")
    src = "ipinfo-lite" if (country or asn or org) else None
    if not src:
        country = ((gl_city.get(ip) or {}) if gl_city else {}).get(
            "country", {}).get("iso_code")
        a = (gl_asn.get(ip) or {}) if gl_asn else {}
        num = a.get("autonomous_system_number")
        asn = str(num) if num else ""
        org = a.get("autonomous_system_organization")
        src = "geolite" if (country or asn or org) else "none"
    return country or None, asn or None, org or None, src


SQL = """UPDATE ip_enrichment SET country=$2, asn=$3, org=$4,
           raw = jsonb_set(coalesce(raw,'{}'::jsonb), '{tiered}',
                   coalesce(raw->'tiered','{}'::jsonb)
                   || jsonb_build_object('geo_source',$5::text,
                                         'geo_backfill_at',$6::text), true)
         WHERE src_ip=$1"""


async def main():
    pool = await asyncpg.create_pool(
        host=os.environ["PG_HOST"], port=int(os.environ["PG_PORT"]),
        database=os.environ["PG_DB"],
        # Same rule as worker._db_creds: the service account is used only when
        # it actually has a password, otherwise fall back to the main user.
        user=(os.environ.get("SVC_DB_USER") if os.environ.get("SVC_DB_PASSWORD")
              else os.environ["PG_USER"]),
        password=(os.environ.get("SVC_DB_PASSWORD")
                  or os.environ["PG_PASSWORD"]),
        min_size=1, max_size=2)
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT host(src_ip) AS ip, country, asn, org FROM ip_enrichment")

    updates, changed_country, gained, sources = [], 0, 0, {}
    for r in rows:
        c, a, o, src = geo(r["ip"])
        sources[src] = sources.get(src, 0) + 1
        if (c, a, o) == (r["country"], r["asn"], r["org"]):
            continue
        if r["country"] and c and r["country"] != c:
            changed_country += 1
        if not r["country"] and c:
            gained += 1
        updates.append((r["ip"], c, a, o, src, NOW))

    print(f"rows examined      : {len(rows)}")
    print(f"geo source now     : " + ", ".join(f"{k}={v}" for k, v in sorted(sources.items())))
    print(f"rows to update     : {len(updates)}")
    print(f"  country changed  : {changed_country}")
    print(f"  country gained   : {gained}  (was NULL)")

    if not APPLY:
        print("\nDRY RUN — nothing written. Set APPLY=1 to write.")
        return

    done = 0
    async with pool.acquire() as con:
        for i in range(0, len(updates), 1000):
            batch = updates[i:i + 1000]
            async with con.transaction():
                await con.executemany(SQL, batch)
            done += len(batch)
            print(f"  committed {done}/{len(updates)}", flush=True)
    print(f"\nAPPLIED — {done} rows updated (geo only)")
    await pool.close()

asyncio.run(main())
