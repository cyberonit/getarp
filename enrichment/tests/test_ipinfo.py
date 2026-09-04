"""
Acceptance tests for the IPinfo Lite source.

IPinfo is metadata, not intelligence: it answers "where is this IP and whose
ASN is it", never "is it hostile". Three properties matter and are asserted
here rather than assumed:

  * it cannot move a verdict — no reputation, no is_known_attacker, no
    confidence, whatever the source returns;
  * enrichment spends no per-request quota on geo — `tiered` reads the bulk
    IPinfoLiteFeed database, so api.ipinfo.io is never called however much
    traffic goes through; and
  * where it and GeoLite2 disagree on country, IPinfo wins — deliberately,
    and the order that decides it is asserted rather than left to chance.

The per-request IPinfoProvider is still covered below: it remains the
standalone ENRICHMENT_PROVIDER=ipinfo path and part of the `multi` fan-out.
"""
import os

import feeds as feeds_mod
import providers as providers_mod
from conftest import SpyResponse, make_tiered, seed_ip

TOKEN = {"IPINFO_TOKEN": "test-token"}


# ───────────────────────── provider in isolation ─────────────────────────

async def test_parses_lite_payload_and_normalizes_asn(spy):
    """The bare ASN number is stored, not the AS-prefixed string: geolite and
    virustotal both write it bare, and a merged asn field that flips format
    depending on which source answered is not a usable column."""
    p = providers_mod.IPinfoProvider(TOKEN)
    e = await p.enrich("8.8.8.8")

    assert e.country == "XX"
    assert e.asn == "64500", f"expected bare ASN, got {e.asn!r}"
    assert e.org == "SpyGeo"


async def test_never_sets_a_reputation(spy):
    """A metadata source must not be able to clear or raise a verdict."""
    p = providers_mod.IPinfoProvider(TOKEN)
    e = await p.enrich("8.8.8.8")

    assert e.reputation == "unknown"
    assert e.is_known_attacker is False
    assert e.confidence == 0.0
    assert e.categories == []


async def test_no_token_makes_no_request(spy):
    p = providers_mod.IPinfoProvider({})
    e = await p.enrich("8.8.8.8")

    assert spy.count("ipinfo") == 0
    assert e.categories == ["api-key-missing"]


async def test_cache_serves_repeat_lookups(spy):
    p = providers_mod.IPinfoProvider(TOKEN)
    for _ in range(5):
        await p.enrich("8.8.8.8")
    assert spy.count("ipinfo") == 1, "geo/ASN was re-fetched for a cached IP"

    await p.enrich("1.1.1.1")
    assert spy.count("ipinfo") == 2, "a different IP must still be looked up"


async def test_bogon_is_a_cached_answer(spy):
    """Private/reserved space returns {"bogon": true} with no geo — a
    definitive answer, so it must not be re-requested."""
    spy.responses.append(("api.ipinfo.io",
                          SpyResponse(payload={"ip": "10.0.0.1", "bogon": True})))
    p = providers_mod.IPinfoProvider(TOKEN)

    e = await p.enrich("10.0.0.1")
    assert e.country is None and e.asn is None
    assert e.categories == ["bogon"]

    await p.enrich("10.0.0.1")
    assert spy.count("ipinfo") == 1, "bogon answer was not cached"


async def test_429_backs_off_instead_of_hammering(spy):
    spy.responses.append(("api.ipinfo.io",
                          SpyResponse(status_code=429, headers={"Retry-After": "600"})))
    p = providers_mod.IPinfoProvider(TOKEN)

    first = await p.enrich("8.8.8.8")
    assert first.raw["rate_limited"] and first.raw["retry_after"] == 600

    for ip in ("1.1.1.1", "9.9.9.9"):
        assert (await p.enrich(ip)).raw["rate_limited"]
    assert spy.count("ipinfo") == 1, "kept requesting while rate limited"


async def test_rejected_token_stops_further_requests(spy):
    """A bad token fails identically for every IP; one rejected request is a
    diagnosis, one per enrichment is a self-inflicted flood."""
    spy.responses.append(("api.ipinfo.io", SpyResponse(status_code=403)))
    p = providers_mod.IPinfoProvider(TOKEN)

    e = await p.enrich("8.8.8.8")
    assert e.categories == ["api-key-invalid"]
    assert e.raw["auth_failed"] and e.raw["status"] == 403

    await p.enrich("1.1.1.1")
    assert spy.count("ipinfo") == 1, "kept spending requests on a rejected token"


async def test_optional_daily_budget_is_enforced_when_set(spy):
    """Lite is free, so there is no default budget — but the knob must work
    for anyone who wants a hard ceiling."""
    p = providers_mod.IPinfoProvider({**TOKEN, "IPINFO_DAILY_QUOTA": 2})
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
        await p.enrich(ip)
    assert spy.count("ipinfo") == 2

    e = await p.enrich("5.5.5.5")
    assert e.raw["quota_exhausted"] and e.raw["daily_count"] == 2


async def test_http_failure_is_contained(spy):
    spy.routes.append(("api.ipinfo.io", RuntimeError("connection reset")))
    p = providers_mod.IPinfoProvider(TOKEN)

    e = await p.enrich("8.8.8.8")
    assert "connection reset" in e.raw["error"]
    assert e.country is None and e.reputation == "unknown"


# ───────────────────────── the bulk feed (Tier 1) ─────────────────────────

class FakeReader:
    """Stands in for a maxminddb reader: same .get(ip) surface, no file."""

    def __init__(self, records: dict):
        self._records = records
        self.closed = False

    def get(self, ip):
        return self._records.get(ip)

    def close(self):
        self.closed = True


IPINFO_REC = {"country": "NL", "country_name": "Netherlands", "asn": "AS206264",
              "as_name": "Amarutu Technology Ltd", "as_domain": "koddos.net",
              "continent": "EU"}


def make_feed(tmp_path, records=None, **extra) -> feeds_mod.IPinfoLiteFeed:
    f = feeds_mod.IPinfoLiteFeed({"GEOIP_DIR": str(tmp_path), **TOKEN, **extra})
    if records is not None:
        f._reader = FakeReader(records)
    return f


async def test_feed_lookup_is_metadata_only(tmp_path):
    feed = make_feed(tmp_path, {"5.61.209.43": IPINFO_REC})
    e = feed.lookup("5.61.209.43")

    assert e.country == "NL"
    assert e.asn == "206264", f"expected bare ASN, got {e.asn!r}"
    assert e.org == "Amarutu Technology Ltd"
    assert e.raw["as_domain"] == "koddos.net"
    assert e.reputation == "unknown"
    assert e.is_known_attacker is False and e.confidence == 0.0
    assert e.categories == []


async def test_feed_misses_return_none(tmp_path):
    feed = make_feed(tmp_path, {"5.61.209.43": IPINFO_REC})
    assert feed.lookup("192.0.2.99") is None
    assert make_feed(tmp_path).lookup("5.61.209.43") is None, "no database loaded"


async def test_feed_is_inactive_without_a_token(tmp_path, spy):
    feed = feeds_mod.IPinfoLiteFeed({"GEOIP_DIR": str(tmp_path)})
    await feed.refresh(None)

    assert spy.count("ipinfo-lite") == 0
    assert feed.lookup("5.61.209.43") is None


# ───────────────────────── download behaviour ─────────────────────────

def _db_bytes(size=feeds_mod.IPinfoLiteFeed._MIN_BYTES + 1) -> bytes:
    return b"\x00" * size


async def test_download_sends_the_token_as_a_header_not_in_the_url(tmp_path, spy):
    """The admin UI can read this container's logs, and a failed download logs
    its exception — so the token must never be in a URL."""
    spy.responses.append(("ipinfo.io/data/free", SpyResponse(content=_db_bytes())))
    await make_feed(tmp_path).refresh(None)

    url, kwargs = next((u, k) for u, k in spy.seen if "ipinfo.io/data/free" in u)
    assert "test-token" not in url
    assert kwargs["headers"]["Authorization"] == "Bearer test-token"


async def test_truncated_download_never_replaces_a_good_database(tmp_path, spy):
    """A short read that still parses would silently shrink coverage."""
    feed = make_feed(tmp_path, {"5.61.209.43": IPINFO_REC})
    good = feed._path
    with open(good, "wb") as fh:
        fh.write(b"previous database")
    os.utime(good, (0, 0))          # stale, so refresh will try to download

    spy.responses.append(("ipinfo.io/data/free", SpyResponse(content=b"truncated")))
    await feed.refresh(None)

    assert open(good, "rb").read() == b"previous database"
    assert not os.path.exists(good + ".part"), "partial download left behind"
    assert feed.lookup("5.61.209.43").country == "NL", "working index was dropped"


async def test_download_is_skipped_while_the_database_is_fresh(tmp_path, spy):
    """Upstream rebuilds daily; re-fetching 23 MB every feed cycle is waste."""
    feed = make_feed(tmp_path)
    with open(feed._path, "wb") as fh:
        fh.write(b"recent")

    await feed.refresh(None)
    assert spy.count("ipinfo-lite") == 0

    os.utime(feed._path, (0, 0))    # older than IPINFO_DB_MAX_AGE_HOURS
    spy.responses.append(("ipinfo.io/data/free", SpyResponse(content=_db_bytes())))
    await feed.refresh(None)
    assert spy.count("ipinfo-lite") == 1


async def test_failed_download_keeps_serving_the_previous_index(tmp_path, spy):
    """feeds.py's fail-safe contract: refresh() never raises and never leaves
    the feed worse off than before."""
    feed = make_feed(tmp_path, {"5.61.209.43": IPINFO_REC})
    spy.routes.append(("ipinfo.io/data/free", RuntimeError("connection reset")))

    await feed.refresh(None)        # must not raise

    assert feed.lookup("5.61.209.43").country == "NL"


# ───────────────────────── precedence against geolite ─────────────────────────

async def test_ipinfo_is_consulted_before_geolite():
    order = [f.name for f in feeds_mod.get_feed_providers({})]
    assert order.index("ipinfo-lite") < order.index("geolite"), (
        f"geo precedence depends on this order, got {order}")


async def test_ipinfo_wins_the_country_when_the_two_disagree(pool, spy):
    """GeoLite2 reports the LIR's registered country, IPinfo where the range is
    routed. For hosts behind shell companies the routed answer is the useful
    one, so IPinfo takes precedence — and geolite is still recorded in raw."""
    ip = "5.61.209.43"
    await seed_ip(pool, ip)
    tiered = await make_tiered(pool, **TOKEN)
    tiered.feed_providers = [_ipinfo_feed_with({ip: IPINFO_REC}),
                             _geolite_feed_with(ip, "SC", "206264",
                                                "Amarutu Technology Ltd")]

    result = await tiered.enrich(ip)

    assert result.country == "NL", "GeoLite2's registered country won"
    assert result.raw["tiered"]["geo_source"] == "ipinfo-lite"
    assert result.raw["geolite"]["reputation"] == "unknown"


async def test_geolite_fills_what_ipinfo_misses(pool, spy):
    ip = "192.0.2.40"
    await seed_ip(pool, ip)
    tiered = await make_tiered(pool, **TOKEN)
    tiered.feed_providers = [_ipinfo_feed_with({}),
                             _geolite_feed_with(ip, "DE", "3320", "Deutsche Telekom AG")]

    result = await tiered.enrich(ip)

    assert result.country == "DE" and result.org == "Deutsche Telekom AG"
    assert result.raw["tiered"]["geo_source"] == "geolite"


async def test_geo_costs_no_per_request_api_calls(pool, spy):
    """The whole point of moving IPinfo to a feed: enrichment must never touch
    api.ipinfo.io, however many IPs go through it."""
    tiered = await make_tiered(pool, **TOKEN)
    tiered.feed_providers = [_ipinfo_feed_with(
        {f"192.0.2.{i}": IPINFO_REC for i in range(1, 20)})]

    for i in range(1, 20):
        ip = f"192.0.2.{i}"
        await seed_ip(pool, ip)
        result = await tiered.enrich(ip)
        assert result.country == "NL"

    assert spy.count("ipinfo") == 0, "the per-request API was called"
    assert spy.count("ipinfo-lite") == 0, "a lookup triggered a download"


async def test_no_geo_at_all_is_recorded_as_such(pool, spy):
    ip = "192.0.2.41"
    await seed_ip(pool, ip)
    tiered = await make_tiered(pool, **TOKEN)
    tiered.feed_providers = [_ipinfo_feed_with({})]

    result = await tiered.enrich(ip)
    assert result.raw["tiered"]["geo_source"] == "none"


# ───────────────────────────── helpers ─────────────────────────────

def _ipinfo_feed_with(records: dict) -> feeds_mod.IPinfoLiteFeed:
    f = feeds_mod.IPinfoLiteFeed({"GEOIP_DIR": "/nonexistent", **TOKEN})
    f._reader = FakeReader(records)
    return f


def _geolite_feed_with(ip: str, country: str, asn: str, org: str):
    """The real GeoLiteFeed reading two stubbed maxminddb readers."""
    f = feeds_mod.GeoLiteFeed({"GEOIP_DIR": "/nonexistent"})
    f._readers = {"city": FakeReader({ip: {"country": {"iso_code": country}}}),
                  "asn": FakeReader({ip: {"autonomous_system_number": int(asn),
                                          "autonomous_system_organization": org}})}
    return f
