"""
Acceptance tests for the two-tier enrichment restructure.

The point of the tiering is QUOTA: Tier-1 local feeds and the durable Postgres
cache must absorb the bulk of honeypot volume so that scarce Tier-2 per-request
APIs (GreyNoise, AbuseIPDB, VirusTotal) are only spent on IPs that earn it.
Every test asserts on SpyAsyncClient call counts — i.e. on actual would-be API
spend — not on internal flags.
"""
import asyncio

import pytest

import feeds as feeds_mod
import providers as providers_mod
import worker as worker_mod
from base import Enrichment
from conftest import (BASE_SETTINGS, CountingProvider, FakeRedis,
                      SpyAsyncClient, SpyResponse, drive_consume, make_tiered,
                      seed_feed, seed_ip)

PAID = ("abuseipdb", "virustotal")
TIER2 = ("greynoise",) + PAID


def _tier2_calls(spy) -> dict[str, int]:
    return {name: spy.count(name) for name in TIER2}


async def test_tier1_covers_known_ip_zero_api_calls(pool, spy):
    """An IP already in a local feed must be fully resolved by Tier 1 —
    zero per-request API calls of any kind."""
    ip = "198.51.100.10"
    await seed_ip(pool, ip, event_count=3, threat_score=0)
    await seed_feed(pool, "feodo", [ip], category="feodo-c2")

    tiered = await make_tiered(pool)
    result = await tiered.enrich(ip)

    assert result.reputation == "malicious"
    assert result.is_known_attacker
    calls = _tier2_calls(spy)
    assert calls == {"greynoise": 0, "abuseipdb": 0, "virustotal": 0}, (
        f"Tier-1 hit must not spend Tier-2 quota, but spent: "
        f"{ {k: v for k, v in calls.items() if v} }")


async def test_cache_prevents_reenrichment(pool):
    """Within ENRICHMENT_CACHE_TTL_DAYS the worker must not re-enrich an IP;
    past the TTL it must."""
    ip = "198.51.100.20"
    await seed_ip(pool, ip)
    provider = CountingProvider()
    r = FakeRedis()

    await r.xadd("enrich:queue", {"src_ip": ip})
    await drive_consume(pool, r, provider, until_acked=1)
    assert provider.calls == [ip]
    async with pool.acquire() as con:
        first = await con.fetchrow(
            "SELECT provider, updated_at FROM ip_enrichment WHERE src_ip=$1", ip)
    assert first is not None

    # Second event for the same IP inside the TTL window: cached, no new call.
    await r.xadd("enrich:queue", {"src_ip": ip})
    await drive_consume(pool, r, provider, until_acked=2)
    assert provider.calls == [ip], "cached IP was re-enriched inside TTL"
    async with pool.acquire() as con:
        second = await con.fetchrow(
            "SELECT provider, updated_at FROM ip_enrichment WHERE src_ip=$1", ip)
    assert second == first, "cached row must be returned untouched"

    # Fast-forward past the TTL: the same event must now re-enrich.
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE ip_enrichment SET updated_at = now() - interval '15 days' "
            "WHERE src_ip=$1", ip)
    await r.xadd("enrich:queue", {"src_ip": ip})
    await drive_consume(pool, r, provider, until_acked=3)
    assert provider.calls == [ip, ip], "expired IP was not re-enriched"


async def test_threshold_gates_tier2(pool, spy):
    """Paid APIs must not run for low-signal IPs, and must run for IPs above
    the threat threshold."""
    low, high = "192.0.2.1", "192.0.2.2"
    await seed_ip(pool, low, event_count=1, threat_score=0)
    await seed_ip(pool, high, event_count=50, threat_score=80)
    tiered = await make_tiered(pool)

    await tiered.enrich(low)
    paid_after_low = sum(spy.count(p) for p in PAID)
    assert paid_after_low == 0, (
        f"paid Tier-2 APIs ran for a 1-event IP: {_tier2_calls(spy)}")

    await tiered.enrich(high)
    paid_after_high = sum(spy.count(p) for p in PAID)
    assert paid_after_high >= 1, "no paid Tier-2 API ran for a high-threat IP"


async def test_virustotal_off_by_default(pool, spy):
    """VirusTotal must be strictly opt-in (VT_ENABLE=true): with default
    config it must not even be constructed, let alone called."""
    ip = "192.0.2.3"
    await seed_ip(pool, ip, event_count=50, threat_score=80)
    tiered = await make_tiered(pool)  # no VIRUSTOTAL_KEY, no VT_ENABLE

    assert "virustotal" not in [p.name for p in tiered._tier2]
    await tiered.enrich(ip)
    assert spy.count("virustotal") == 0

    # Even with a key configured, VT stays off until VT_ENABLE=true.
    tiered_with_key = await make_tiered(pool, VIRUSTOTAL_KEY="some-key")
    assert "virustotal" not in [p.name for p in tiered_with_key._tier2]


async def test_greynoise_only_for_interesting_ips(pool, spy):
    """GreyNoise runs only for IPs crossing the threat threshold — never for
    drive-by single-packet IPs."""
    driveby, interesting = "192.0.2.10", "192.0.2.11"
    await seed_ip(pool, driveby, event_count=1, threat_score=0)
    await seed_ip(pool, interesting, event_count=50, threat_score=80)
    tiered = await make_tiered(pool)

    await tiered.enrich(driveby)
    assert spy.count("greynoise") == 0, "GreyNoise spent on a drive-by IP"

    await tiered.enrich(interesting)
    assert spy.count("greynoise") >= 1, "GreyNoise not used above threshold"


async def test_feed_download_failure_is_safe(pool, spy, capsys):
    """A failing feed download must be logged, must not raise, and must keep
    serving the previously cached feed."""
    ip = "198.51.100.30"
    await seed_feed(pool, "feodo", [ip], category="feodo-c2")
    feed = feeds_mod.AbuseChFeodoFeed(dict(BASE_SETTINGS))
    await feed.load(pool)
    assert feed.lookup(ip) is not None

    spy.routes.append(("feodotracker.abuse.ch", ConnectionError("network down")))
    await feed.refresh(pool)  # must not raise

    assert feed.lookup(ip) is not None, "cached feed lost after failed refresh"
    hit = feed.lookup(ip)
    assert hit.reputation == "malicious"
    out = capsys.readouterr().out
    assert "refresh failed" in out, "feed failure was not logged"

    # And the wrapper loop in the worker survives a feed whose refresh() itself
    # raises (belt-and-braces: feeds shouldn't raise, the loop must still cope).
    class ExplodingFeed:
        name = "exploding"

        async def load(self, pool): ...

        async def refresh(self, pool):
            raise RuntimeError("boom")

    class Holder:
        feed_providers = [ExplodingFeed()]

    task = asyncio.get_event_loop().create_task(
        worker_mod.feed_refresh_loop(pool, Holder()))
    await asyncio.sleep(0.05)
    assert not task.done(), "feed_refresh_loop died on a raising feed"
    task.cancel()
    out = capsys.readouterr().out
    assert "refresh failed" in out


def test_merge_logic_preserved():
    """Worst-of reputation, max confidence, union of categories, first
    non-null geo — the original multi-provider merge semantics."""
    ip = "192.0.2.50"
    verdict_bad = Enrichment(src_ip=ip, provider="a", reputation="malicious",
                             confidence=0.9, categories=["c2", "botnet"],
                             is_known_attacker=True)
    verdict_clean = Enrichment(src_ip=ip, provider="b", reputation="clean",
                               confidence=0.3, categories=["benign-scanner"],
                               country="DE", asn="64500", org="ExampleNet")

    merged = providers_mod.merge_enrichments(
        ip, "multi", [("a", verdict_bad), ("b", verdict_clean)])

    assert merged.reputation == "malicious", "worst-of reputation must win"
    assert merged.confidence == 0.9, "max confidence must win"
    assert set(merged.categories) == {"c2", "botnet", "benign-scanner"}
    assert merged.is_known_attacker
    assert (merged.country, merged.asn, merged.org) == ("DE", "64500", "ExampleNet")
    assert "a" in merged.raw and "b" in merged.raw, "per-provider raw lost"


async def test_end_to_end_quota_budget(pool, spy):
    """HEADLINE: 1000 enrich events, 50 distinct IPs (30 in local feeds,
    5 above the Tier-2 threshold, 15 drive-by) must cost <= 5 Tier-2 calls."""
    feed_ips = [f"198.51.100.{i}" for i in range(100, 130)]   # 30 in Tier-1 feed
    high_ips = [f"203.0.113.{i}" for i in range(1, 6)]        # 5 high-threat
    driveby_ips = [f"192.0.2.{i}" for i in range(100, 115)]   # 15 drive-by
    all_ips = feed_ips + high_ips + driveby_ips
    assert len(all_ips) == 50

    for ip in feed_ips + driveby_ips:
        await seed_ip(pool, ip, event_count=1, threat_score=0)
    for ip in high_ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    await seed_feed(pool, "feodo", feed_ips, category="feodo-c2")

    # Realistic scenario: IPs hammering a honeypot hard enough to cross the
    # threshold are almost always mass scanners GreyNoise recognises, so its
    # verdict is conclusive and no paid escalation is needed. (The escalation
    # path for GreyNoise-unknown IPs is covered by test_threshold_gates_tier2,
    # where the spy's default GreyNoise answer is inconclusive.)
    SpyAsyncClient.responses.append(
        ("greynoise.io", SpyResponse(payload={"classification": "malicious",
                                              "name": "MassScanner"})))

    tiered = await make_tiered(pool)
    r = FakeRedis()
    for i in range(1000):
        await r.xadd("enrich:queue", {"src_ip": all_ips[i % 50]})
    await drive_consume(pool, r, tiered, until_acked=1000, timeout=120)

    calls = _tier2_calls(spy)
    paid = sum(calls[p] for p in PAID)
    total = sum(calls.values())
    print(f"\n[HEADLINE] 1000 events / 50 IPs -> Tier-2 API calls: "
          f"total={total} (greynoise={calls['greynoise']}, "
          f"abuseipdb={calls['abuseipdb']}, virustotal={calls['virustotal']}), "
          f"paid={paid}")

    async with pool.acquire() as con:
        enriched = await con.fetchval("SELECT count(*) FROM ip_enrichment")
    assert enriched == 50, "every distinct IP must still get an enrichment row"

    assert total <= 5, (
        f"tiering budget blown: {total} Tier-2 calls for 1000 events "
        f"(expected <= 5): {calls}")
