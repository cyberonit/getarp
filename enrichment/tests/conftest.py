"""
Acceptance-test harness for the two-tier enrichment system.

External dependencies are replaced, never contacted:
  * Postgres — a throwaway instance at TEST_PG_DSN (see tests README in
    docstrings; CI/dev: `docker run timescale/timescaledb` on a local port).
  * HTTP — SpyAsyncClient replaces httpx.AsyncClient for providers.py and
    feeds.py and COUNTS calls per API host, so tests can assert exactly how
    much per-request quota an operation would have spent.
  * Redis — FakeRedis implements just the stream primitives worker.consume
    uses, so the real consume loop can be driven end-to-end.
"""
import asyncio
import contextlib
import json
import os
import sys
import time
from collections import deque

import asyncpg
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import feeds as feeds_mod        # noqa: E402
import providers as providers_mod  # noqa: E402
import worker as worker_mod      # noqa: E402
from base import Enrichment      # noqa: E402

TEST_DSN = os.environ.get(
    "TEST_PG_DSN", "postgresql://postgres@127.0.0.1:55432/postgres")

# Minimal slice of db/init.sql needed by enrichment (no hypertables involved).
SCHEMA = """
CREATE TABLE IF NOT EXISTS ips (
    src_ip        INET PRIMARY KEY,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_count   BIGINT      NOT NULL DEFAULT 0,
    services_hit  TEXT[]      NOT NULL DEFAULT '{}',
    ports_hit     INTEGER[]   NOT NULL DEFAULT '{}',
    threat_score  REAL        NOT NULL DEFAULT 0,
    classification TEXT       DEFAULT 'unknown'
);
CREATE TABLE IF NOT EXISTS ip_enrichment (
    src_ip      INET PRIMARY KEY REFERENCES ips(src_ip) ON DELETE CASCADE,
    provider    TEXT,
    country     TEXT,
    asn         TEXT,
    org         TEXT,
    reputation  TEXT,
    confidence  REAL,
    categories  TEXT[],
    is_known_attacker BOOLEAN,
    updated_at  TIMESTAMPTZ DEFAULT now(),
    raw         JSONB
);
CREATE TABLE IF NOT EXISTS feed_indicators (
    source     TEXT        NOT NULL,
    indicator  INET        NOT NULL,
    type       TEXT        NOT NULL DEFAULT 'ip',
    category   TEXT,
    meta       JSONB,
    updated_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (source, indicator)
);
"""

BASE_SETTINGS = {
    "GREYNOISE_KEY": "test-key",
    "ABUSEIPDB_KEY": "test-key",
    "CROWDSEC_BOUNCER_KEY": "test-key",
    "ABUSECH_KEY": "test-key",
}


# ───────────────────────────── HTTP spy ─────────────────────────────

_HOSTS = {
    "greynoise": "greynoise.io",
    "abuseipdb": "abuseipdb.com",
    "virustotal": "virustotal.com",
    "crowdsec-cti": "cti.api.crowdsec.net",
    "crowdsec-lapi": "crowdsec:8080",
    "feodo": "feodotracker.abuse.ch",
    "threatfox": "threatfox-api.abuse.ch",
}


class SpyResponse:
    def __init__(self, status_code=200, payload=None, headers=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _default_response(url: str) -> SpyResponse:
    if "greynoise.io" in url:
        return SpyResponse(payload={"classification": "unknown", "name": "spy"})
    if "abuseipdb.com" in url:
        return SpyResponse(payload={"data": {"abuseConfidenceScore": 90,
                                             "countryCode": "XX", "isp": "SpyNet"}})
    if "virustotal.com" in url:
        return SpyResponse(payload={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 6, "harmless": 60},
            "country": "XX", "tags": []}}})
    if "crowdsec:8080" in url:
        return SpyResponse(payload=[])
    if "feodotracker" in url:
        return SpyResponse(text="# spy feed\n")
    if "threatfox" in url:
        return SpyResponse(payload={"query_status": "ok", "data": []})
    return SpyResponse()


class SpyAsyncClient:
    """Drop-in for httpx.AsyncClient. Counts calls per known API host.
    Failure injection: SpyAsyncClient.routes.append((url_fragment, exc)).
    Response override: SpyAsyncClient.responses.append((url_fragment, resp))."""
    calls: dict[str, int] = {}
    routes: list[tuple[str, Exception]] = []
    responses: list[tuple[str, SpyResponse]] = []

    def __init__(self, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _hit(self, url: str) -> SpyResponse:
        for name, frag in _HOSTS.items():
            if frag in url:
                SpyAsyncClient.calls[name] = SpyAsyncClient.calls.get(name, 0) + 1
        for frag, exc in SpyAsyncClient.routes:
            if frag in url:
                raise exc
        for frag, resp in SpyAsyncClient.responses:
            if frag in url:
                return resp
        return _default_response(url)

    async def get(self, url, **kwargs):
        return self._hit(url)

    async def post(self, url, **kwargs):
        return self._hit(url)

    @classmethod
    def count(cls, name: str) -> int:
        return cls.calls.get(name, 0)


@pytest.fixture
def spy(monkeypatch):
    SpyAsyncClient.calls = {}
    SpyAsyncClient.routes = []
    SpyAsyncClient.responses = []
    monkeypatch.setattr(providers_mod.httpx, "AsyncClient", SpyAsyncClient)
    monkeypatch.setattr(feeds_mod.httpx, "AsyncClient", SpyAsyncClient)
    yield SpyAsyncClient


# ───────────────────────────── Postgres ─────────────────────────────

@pytest.fixture
async def pool():
    p = await asyncpg.create_pool(dsn=TEST_DSN, min_size=1, max_size=4)
    async with p.acquire() as con:
        await con.execute(SCHEMA)
        await con.execute("TRUNCATE ip_enrichment, feed_indicators, ips CASCADE")
    yield p
    await p.close()


async def seed_ip(pool, ip: str, event_count: int = 1, threat_score: float = 0.0):
    async with pool.acquire() as con:
        await con.execute(
            "INSERT INTO ips (src_ip, event_count, threat_score) VALUES ($1,$2,$3)",
            ip, event_count, threat_score)


async def seed_feed(pool, source: str, ips: list[str], category: str = "test"):
    import ipaddress
    async with pool.acquire() as con:
        await con.executemany(
            """INSERT INTO feed_indicators (source, indicator, type, category, meta)
               VALUES ($1,$2,'ip',$3,$4)""",
            [(source, ipaddress.ip_address(ip), category, json.dumps({}))
             for ip in ips])


async def make_tiered(pool, **extra) -> providers_mod.TieredProvider:
    """TieredProvider bound to the test pool, Tier-1 feeds loaded from
    feed_indicators exactly like worker.feed_refresh_loop does at startup."""
    provider = providers_mod.TieredProvider({**BASE_SETTINGS, **extra})
    provider.bind(pool)
    for f in provider.feed_providers:
        await f.load(pool)
    return provider


# ───────────────────────────── Redis shim ─────────────────────────────

class FakeRedis:
    """Just the stream primitives worker.consume/ensure_group use."""

    def __init__(self):
        self._stream = deque()
        self._next_id = 0
        self.acked = 0
        self.kv = {}

    async def xgroup_create(self, *args, **kwargs):
        pass

    async def xadd(self, stream, fields, **kwargs):
        self._next_id += 1
        self._stream.append((f"{self._next_id}-0",
                             {k: str(v) for k, v in fields.items()}))

    async def xreadgroup(self, group, consumer, streams, count=10, block=0):
        if not self._stream:
            await asyncio.sleep(0.002)
            return None
        batch = [self._stream.popleft()
                 for _ in range(min(count, len(self._stream)))]
        return [("enrich:queue", batch)]

    async def xack(self, *args):
        self.acked += 1

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None):
        self.kv[key] = value


async def drive_consume(pool, r: FakeRedis, provider, until_acked: int,
                        timeout: float = 60.0):
    """Run the REAL worker.consume loop until `until_acked` messages are
    processed, then cancel it."""
    task = asyncio.create_task(worker_mod.consume(pool, r, provider))
    deadline = time.monotonic() + timeout
    try:
        while r.acked < until_acked:
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"consume processed {r.acked}/{until_acked} in {timeout}s")
            await asyncio.sleep(0.01)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    assert r.acked == until_acked


class CountingProvider:
    """Stub provider that records every enrich() call — isolates worker-level
    cache behaviour from provider internals."""
    name = "counting"

    def __init__(self):
        self.calls: list[str] = []

    async def enrich(self, ip: str) -> Enrichment:
        self.calls.append(ip)
        return Enrichment(src_ip=ip, provider=self.name,
                          reputation="clean", confidence=0.1)
