"""
Quota-resilience tests for Tier-2 providers, written after the 2026-07-10
production incident: GreyNoise's community tier turned out to be a small
WEEKLY allowance, its 429s (no Retry-After header) only triggered a 60s
cooldown, and every rate-limited "unknown" escalated to AbuseIPDB — 1400+
calls/day against a 1000/day quota.

These tests simulate real 429 responses and assert on SpyAsyncClient call
counts: the stack must stay within budget even when providers are throttled.
"""
import time

import providers as providers_mod
from conftest import (BASE_SETTINGS, FakeRedis, SpyAsyncClient, SpyResponse,
                      drive_consume, make_tiered, seed_ip)

GN_429 = SpyResponse(status_code=429,
                     payload={"error": "your searches will reset on July 16"})


async def test_greynoise_429_long_backoff(pool, spy, capsys):
    """A GreyNoise 429 without Retry-After must trigger an hours-long cooldown:
    one HTTP call, then stubs — not a retry per enrichment."""
    ips = [f"203.0.113.{i}" for i in range(1, 4)]
    for ip in ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))

    tiered = await make_tiered(pool)
    for ip in ips:
        await tiered.enrich(ip)

    assert spy.count("greynoise") == 1, (
        "GreyNoise hammered while rate limited — cooldown not honored")
    gn = next(p for p in tiered._tier2 if p.name == "greynoise")
    assert gn._rate_limited_until - time.time() > 3600, (
        "429 without Retry-After must back off for hours (weekly quota), "
        f"got {gn._rate_limited_until - time.time():.0f}s")
    assert "rate limited" in capsys.readouterr().out, (
        "entering cooldown must be visible in the logs")


async def test_greynoise_429_still_escalates_within_budget(pool, spy):
    """While GreyNoise is throttled, high-threat IPs must still get a verdict
    from AbuseIPDB (it becomes the primary Tier-2 source), and the answer must
    land in the merged enrichment."""
    ip = "203.0.113.10"
    await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))

    tiered = await make_tiered(pool)
    result = await tiered.enrich(ip)

    assert spy.count("abuseipdb") == 1
    assert result.reputation == "malicious"  # spy default: score 90
    assert result.raw["tiered"]["tier2_ran"] == ["abuseipdb"]
    assert result.raw["tiered"]["tier2_deferred"] == ["greynoise"]


async def test_abuseipdb_daily_budget(pool, spy):
    """AbuseIPDB must stop issuing requests at ABUSEIPDB_DAILY_QUOTA; IPs over
    budget get a retryable 'unknown' row, not an HTTP call the API would 429."""
    ips = [f"203.0.113.{i}" for i in range(20, 25)]  # 5 high-threat IPs
    for ip in ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))

    tiered = await make_tiered(pool, ABUSEIPDB_DAILY_QUOTA="3")
    results = [await tiered.enrich(ip) for ip in ips]

    assert spy.count("abuseipdb") == 3, (
        f"budget of 3 but {spy.count('abuseipdb')} requests went out")
    over_budget = results[3:]
    for r in over_budget:
        assert r.reputation == "unknown", (
            "over-budget IP must stay 'unknown' so the retry loop re-queues it")
        assert "abuseipdb" in r.raw["tiered"]["tier2_deferred"]
        assert r.raw["abuseipdb"].get("quota_exhausted")


async def test_abuseipdb_429_backoff(pool, spy, capsys):
    """A real AbuseIPDB 429 (e.g. quota already spent by an earlier worker run)
    must honor Retry-After and stop the request stream immediately."""
    ips = ["203.0.113.30", "203.0.113.31"]
    for ip in ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))
    spy.responses.append(("abuseipdb.com", SpyResponse(
        status_code=429, headers={"Retry-After": "1800"})))

    tiered = await make_tiered(pool)
    for ip in ips:
        await tiered.enrich(ip)

    assert spy.count("abuseipdb") == 1, "kept calling AbuseIPDB after a 429"
    ab = next(p for p in tiered._tier2 if p.name == "abuseipdb")
    assert 1700 < ab._rate_limited_until - time.time() <= 1800
    assert "backing off 1800s" in capsys.readouterr().out


async def test_quota_storm_end_to_end(pool, spy):
    """HEADLINE (incident replay): GreyNoise fully rate limited, 300 events
    across 20 high-threat IPs, AbuseIPDB budget 10. The old code made one
    GreyNoise call per enrichment and 20 AbuseIPDB calls; now the whole storm
    must cost 1 GreyNoise call and exactly the 10 budgeted AbuseIPDB calls,
    while every IP still gets an enrichment row."""
    ips = [f"198.18.0.{i}" for i in range(1, 21)]
    for ip in ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))

    tiered = await make_tiered(pool, ABUSEIPDB_DAILY_QUOTA="10")
    r = FakeRedis()
    for i in range(300):
        await r.xadd("enrich:queue", {"src_ip": ips[i % 20]})
    await drive_consume(pool, r, tiered, until_acked=300, timeout=120)

    gn_calls, ab_calls = spy.count("greynoise"), spy.count("abuseipdb")
    print(f"\n[HEADLINE] 300 events / 20 IPs under full GreyNoise 429 storm -> "
          f"greynoise={gn_calls}, abuseipdb={ab_calls} (budget 10)")

    assert gn_calls == 1, f"GreyNoise called {gn_calls}x while rate limited"
    assert ab_calls == 10, f"AbuseIPDB budget was 10, spent {ab_calls}"

    async with pool.acquire() as con:
        enriched = await con.fetchval("SELECT count(*) FROM ip_enrichment")
        retryable = await con.fetchval(
            "SELECT count(*) FROM ip_enrichment WHERE reputation = 'unknown'")
    assert enriched == 20, "every IP must still get an enrichment row"
    assert retryable == 10, (
        "the 10 over-budget IPs must stay 'unknown' for the retry loop")


async def test_deferred_stub_costs_nothing(pool, spy):
    """Once both providers are throttled, further enrichments must be
    HTTP-free: stubs only, no request stream at all."""
    ips = [f"198.18.1.{i}" for i in range(1, 11)]
    for ip in ips:
        await seed_ip(pool, ip, event_count=50, threat_score=80)
    spy.responses.append(("greynoise.io", GN_429))

    tiered = await make_tiered(pool, ABUSEIPDB_DAILY_QUOTA="1")
    await tiered.enrich(ips[0])          # spends the GN 429 + the whole budget
    before = dict(spy.calls)
    for ip in ips[1:]:
        await tiered.enrich(ip)
    assert spy.calls == before, (
        f"throttled providers still made HTTP calls: {spy.calls} != {before}")
