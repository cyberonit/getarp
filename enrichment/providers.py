"""Concrete enrichment providers. Add a new one by subclassing + @register."""
import asyncio
import os
import time
import httpx
from base import Enrichment, EnrichmentProvider, _REGISTRY, register


@register
class CrowdSecProvider(EnrichmentProvider):
    """Checks the local CrowdSec LAPI first, then falls back to the CrowdSec
    CTI smoke API when CROWDSEC_CTI_KEY is configured."""
    name = "crowdsec"
    _TTL = 300
    _CTI_URL = "https://cti.api.crowdsec.net/v2/smoke/"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._lapi = settings.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
        self._key = settings.get("CROWDSEC_BOUNCER_KEY", "")
        self._cti_key = settings.get("CROWDSEC_CTI_KEY", "")
        self._decisions: dict[str, list[str]] = {}
        self._last_fetch: float = 0.0
        self._lock = asyncio.Lock()

    async def _refresh(self):
        async with self._lock:
            if time.time() - self._last_fetch < self._TTL:
                return
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    resp = await c.get(f"{self._lapi}/v1/decisions",
                                       headers={"X-Api-Key": self._key})
                raw = resp.json() or []
                local = [d for d in raw if d.get("origin") != "CAPI"]
                new: dict[str, list[str]] = {}
                for d in local:
                    ip = d.get("value")
                    if ip:
                        new.setdefault(ip, []).append(d.get("scenario", ""))
                self._decisions = new
                print(f"[crowdsec] refreshed: {len(new)} banned IPs", flush=True)
            except Exception as ex:
                print(f"[crowdsec] refresh failed: {ex}", flush=True)
            self._last_fetch = time.time()

    async def _cti_lookup(self, ip: str) -> Enrichment | None:
        if not self._cti_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(
                    self._CTI_URL + ip,
                    headers={"x-api-key": self._cti_key})
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                return None
            resp.raise_for_status()
            d = resp.json()
            e = Enrichment(src_ip=ip, provider=self.name)
            e.raw = d
            scores = d.get("scores", {}).get("overall", {})
            total = scores.get("total", 0)
            e.confidence = min(total / 5.0, 1.0)
            e.is_known_attacker = total >= 3
            e.reputation = ("malicious" if total >= 3 else
                            "suspicious" if total >= 1 else "clean")
            loc = d.get("location") or {}
            e.country = loc.get("country")
            e.asn = str(d.get("as_num", "") or "")
            e.org = d.get("as_name")
            cls = d.get("classifications", {})
            cats = [c.get("name") for c in cls.get("classifications", []) if c.get("name")]
            cats += [b.get("name") for b in cls.get("behaviors", []) if b.get("name")]
            e.categories = cats or []
            return e
        except Exception as ex:
            print(f"[crowdsec] CTI lookup failed for {ip}: {ex}", flush=True)
            return None

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        if not self._key and not self._cti_key:
            e.categories = ["no-keys-configured"]
            e.raw = {"source": "none", "reason": "set CROWDSEC_BOUNCER_KEY or CROWDSEC_CTI_KEY"}
            return e
        if self._key:
            if time.time() - self._last_fetch >= self._TTL:
                await self._refresh()
            scenarios = self._decisions.get(ip)
            if scenarios:
                e.reputation = "malicious"
                e.is_known_attacker = True
                e.confidence = 0.9
                e.categories = list({s for s in scenarios if s})
                e.raw = {"source": "lapi", "banned": True, "scenarios": scenarios}
                return e
        cti = await self._cti_lookup(ip)
        if cti:
            return cti
        e.reputation = "unknown"
        e.raw = {"source": "lapi", "banned": False, "scenarios": []}
        return e


@register
class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("ABUSEIPDB_KEY")
        if not key:
            e.categories = ["api-key-missing"]
            return e
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL,
                                   headers={"Key": key, "Accept": "application/json"},
                                   params={"ipAddress": ip, "maxAgeInDays": 90})
            resp.raise_for_status()
            d = resp.json().get("data", {})
            e.raw = d
            score = d.get("abuseConfidenceScore", 0)
            e.confidence = score / 100.0
            e.country = d.get("countryCode")
            e.org = d.get("isp")
            e.is_known_attacker = score >= 50
            e.reputation = ("malicious" if score >= 75 else
                            "suspicious" if score >= 25 else "clean")
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e


@register
class GreyNoiseProvider(EnrichmentProvider):
    """GreyNoise community API with rate-limit awareness.  Backs off on 429 and
    serves cached results for the remainder of the cooldown window."""
    name = "greynoise"
    URL = "https://api.greynoise.io/v3/community/"
    _COOLDOWN = 60

    _MAX_CACHE = 10000

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._cache: dict[str, Enrichment] = {}
        self._cache_ts: dict[str, float] = {}
        self._cache_ttl = 3600
        self._rate_limited_until: float = 0.0

    def _cache_put(self, ip: str, e: Enrichment):
        if len(self._cache) >= self._MAX_CACHE:
            oldest = min(self._cache_ts, key=self._cache_ts.get)
            del self._cache[oldest], self._cache_ts[oldest]
        self._cache[ip] = e
        self._cache_ts[ip] = time.time()

    async def enrich(self, ip: str) -> Enrichment:
        now = time.time()
        cached = self._cache.get(ip)
        if cached and now - self._cache_ts.get(ip, 0) < self._cache_ttl:
            return cached

        e = Enrichment(src_ip=ip, provider=self.name)

        if now < self._rate_limited_until:
            e.reputation = "unknown"
            e.raw = {"rate_limited": True,
                     "retry_after": int(self._rate_limited_until - now)}
            return e

        key = self.settings.get("GREYNOISE_KEY")
        headers = {"key": key} if key else {}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL + ip, headers=headers)
            if resp.status_code == 429:
                retry = int(resp.headers.get("Retry-After", self._COOLDOWN))
                self._rate_limited_until = now + retry
                e.reputation = "unknown"
                e.raw = {"rate_limited": True, "retry_after": retry}
                return e
            if resp.status_code == 404:
                e.reputation = "unknown"
                e.raw = {"not_observed": True}
                self._cache_put(ip, e)
                return e
            resp.raise_for_status()
            d = resp.json()
            e.raw = d
            cls = d.get("classification", "unknown")
            e.reputation = {"malicious": "malicious", "benign": "clean"}.get(cls, "unknown")
            e.is_known_attacker = cls == "malicious"
            e.org = d.get("name")
            e.categories = [cls]
            e.confidence = 0.8 if cls == "malicious" else 0.3
        except Exception as ex:
            e.raw = {"error": str(ex)}
        self._cache_put(ip, e)
        return e


@register
class VirusTotalProvider(EnrichmentProvider):
    """VirusTotal IP reputation via the v3 API. Requires a free API key.

    Free-tier limits: 500 requests/day, 4 requests/minute.
    This provider tracks both and serves cached results when limits are near."""
    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/ip_addresses/"

    _MAX_CACHE = 10000
    _DEFAULT_DAILY_QUOTA = 480
    _MIN_REQUEST_INTERVAL = 15.5

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._cache: dict[str, Enrichment] = {}
        self._cache_ts: dict[str, float] = {}
        self._cache_ttl = 86400
        self._daily_quota = int(settings.get("VT_DAILY_QUOTA", self._DEFAULT_DAILY_QUOTA))
        self._daily_count = 0
        self._daily_reset: float = 0.0
        self._last_request: float = 0.0
        self._rate_limited_until: float = 0.0
        self._lock = asyncio.Lock()

    def _cache_put(self, ip: str, e: Enrichment):
        if len(self._cache) >= self._MAX_CACHE:
            oldest = min(self._cache_ts, key=self._cache_ts.get)
            del self._cache[oldest], self._cache_ts[oldest]
        self._cache[ip] = e
        self._cache_ts[ip] = time.time()

    def _reset_daily_if_needed(self):
        now = time.time()
        if now >= self._daily_reset:
            self._daily_count = 0
            midnight = now - (now % 86400) + 86400
            self._daily_reset = midnight

    async def enrich(self, ip: str) -> Enrichment:
        now = time.time()

        cached = self._cache.get(ip)
        if cached and now - self._cache_ts.get(ip, 0) < self._cache_ttl:
            return cached

        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("VIRUSTOTAL_KEY")
        if not key:
            e.categories = ["api-key-missing"]
            return e

        self._reset_daily_if_needed()
        if self._daily_count >= self._daily_quota:
            e.reputation = "unknown"
            e.raw = {"quota_exhausted": True,
                     "daily_count": self._daily_count,
                     "resets_at": int(self._daily_reset)}
            return e

        if now < self._rate_limited_until:
            e.reputation = "unknown"
            e.raw = {"rate_limited": True,
                     "retry_after": int(self._rate_limited_until - now)}
            return e

        async with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < self._MIN_REQUEST_INTERVAL:
                await asyncio.sleep(self._MIN_REQUEST_INTERVAL - elapsed)

            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    resp = await c.get(self.URL + ip, headers={"x-apikey": key})
                self._last_request = time.time()
                self._daily_count += 1

                if resp.status_code == 429:
                    retry = int(resp.headers.get("Retry-After", 60))
                    self._rate_limited_until = time.time() + retry
                    e.reputation = "unknown"
                    e.raw = {"rate_limited": True, "retry_after": retry}
                    return e

                if resp.status_code == 404:
                    e.reputation = "clean"
                    self._cache_put(ip, e)
                    return e

                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
                e.raw = attrs
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                e.confidence = malicious / total
                e.country = attrs.get("country")
                e.asn = str(attrs.get("asn", "") or "")
                e.org = attrs.get("as_owner")
                e.is_known_attacker = malicious >= 5
                e.reputation = ("malicious" if malicious >= 5 else
                                "suspicious" if malicious >= 1 or suspicious >= 3 else "clean")
                e.categories = attrs.get("tags", [])
            except Exception as ex:
                e.raw = {"error": str(ex)}

        self._cache_put(ip, e)
        return e


@register
class AbusechProvider(EnrichmentProvider):
    """Abuse.ch provider. Uses the ThreatFox API when ABUSECH_KEY is set,
    falls back to the public Feodo Tracker IP blocklist otherwise."""
    name = "abusech"
    _THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    _BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    _CACHE_PATH = os.path.join("/tmp", "feodo_ipblocklist.txt")
    _TTL = 3600

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._key = settings.get("ABUSECH_KEY")
        self._blacklist: set[str] = set()
        self._last_fetch: float = 0.0
        self._lock = asyncio.Lock()
        self._load_cache_sync()

    def _load_cache_sync(self):
        try:
            if os.path.exists(self._CACHE_PATH):
                with open(self._CACHE_PATH, encoding="utf-8") as f:
                    self._blacklist = self._parse(f.read())
                self._last_fetch = os.path.getmtime(self._CACHE_PATH)
        except Exception:
            pass

    @staticmethod
    def _parse(text: str) -> set[str]:
        result = set()
        for line in text.splitlines():
            line = line.strip()
            if line and line[0] not in "#;":
                result.add(line.split()[0])
        return result

    async def _refresh_blocklist(self):
        async with self._lock:
            if time.time() - self._last_fetch < self._TTL:
                return
            text = None
            for attempt in range(4):
                try:
                    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
                        resp = await c.get(self._BLOCKLIST_URL)
                    if resp.status_code == 200 and resp.text.strip():
                        text = resp.text
                        break
                    if resp.status_code in (429,) or resp.status_code >= 500:
                        await asyncio.sleep(int(resp.headers.get("Retry-After", 2 ** attempt)))
                except Exception:
                    await asyncio.sleep(2 ** attempt)
            if text is not None:
                os.makedirs(os.path.dirname(self._CACHE_PATH), exist_ok=True)
                with open(self._CACHE_PATH, "w", encoding="utf-8") as f:
                    f.write(text)
                self._blacklist = self._parse(text)
                print(f"[abusech] blocklist refreshed: {len(self._blacklist)} IPs", flush=True)
            self._last_fetch = time.time()

    async def _threatfox_lookup(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        # always check blocklist first
        if time.time() - self._last_fetch >= self._TTL:
            await self._refresh_blocklist()
        if ip in self._blacklist:
            e.reputation = "malicious"
            e.is_known_attacker = True
            e.confidence = 0.9
            e.categories = ["feodo-c2"]
            return e
        # fall through to ThreatFox API
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                resp = await c.post(
                    self._THREATFOX_URL,
                    headers={"Auth-Key": self._key},
                    json={"query": "search_ioc", "search_term": ip, "exact_match": True},
                )
                resp.raise_for_status()
            data = resp.json()
            e.raw = data
            hits = data.get("data") if isinstance(data.get("data"), list) else []
            if hits:
                e.reputation = "malicious"
                e.is_known_attacker = True
                e.confidence = 0.9
                tags = set()
                for h in hits:
                    for t in h.get("tags", []) or []:
                        tags.add(t)
                e.categories = sorted(tags) if tags else ["abusech-threatfox"]
            else:
                e.reputation = "unknown"
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e

    async def enrich(self, ip: str) -> Enrichment:
        if self._key:
            return await self._threatfox_lookup(ip)
        e = Enrichment(src_ip=ip, provider=self.name)
        if time.time() - self._last_fetch >= self._TTL:
            await self._refresh_blocklist()
        if ip in self._blacklist:
            e.reputation = "malicious"
            e.is_known_attacker = True
            e.confidence = 0.9
            e.categories = ["feodo-c2"]
            e.raw = {"source": "feodo-blocklist", "listed": True,
                     "blocklist_size": len(self._blacklist)}
        else:
            e.reputation = "unknown"
            e.raw = {"source": "feodo-blocklist", "listed": False,
                     "blocklist_size": len(self._blacklist)}
        return e


_REP_SEVERITY = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


def merge_enrichments(ip: str, provider_name: str,
                      named_results: list[tuple[str, Enrichment | Exception]]) -> Enrichment:
    """Merge per-provider results: worst-of reputation, max confidence, union of
    categories, first non-null country/asn/org. Per-provider raw kept for audit."""
    merged = Enrichment(src_ip=ip, provider=provider_name)
    merged.raw = {}

    for name, result in named_results:
        if isinstance(result, Exception):
            merged.raw[name] = {"error": str(result)}
            continue
        praw = dict(result.raw) if isinstance(result.raw, dict) else {}
        praw["reputation"] = result.reputation
        merged.raw[name] = praw

        if _REP_SEVERITY.get(result.reputation, 0) > _REP_SEVERITY.get(merged.reputation, 0):
            merged.reputation = result.reputation

        if result.confidence > merged.confidence:
            merged.confidence = result.confidence

        if result.is_known_attacker:
            merged.is_known_attacker = True

        if not merged.country and result.country:
            merged.country = result.country
        if not merged.asn and result.asn:
            merged.asn = result.asn
        if not merged.org and result.org:
            merged.org = result.org

        for cat in result.categories:
            if cat and cat not in merged.categories:
                merged.categories.append(cat)

    return merged


@register
class MultiProvider(EnrichmentProvider):
    """Queries all other registered providers in parallel and merges results.
    Set ENRICHMENT_PROVIDER=multi to activate."""
    name = "multi"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._providers = [cls(settings) for name, cls in _REGISTRY.items()
                           if name not in (self.name, "tiered")]

    async def enrich(self, ip: str) -> Enrichment:
        providers = self._providers
        results = await asyncio.gather(
            *[p.enrich(ip) for p in providers], return_exceptions=True)
        return merge_enrichments(ip, self.name,
                                 [(p.name, r) for p, r in zip(providers, results)])


@register
class TieredProvider(EnrichmentProvider):
    """Two-tier enrichment (the default mode, ENRICHMENT_PROVIDER=tiered).

    Tier 1 — local feeds (feeds.py): abuse.ch blocklists, the local CrowdSec
    engine's decisions (incl. the free CAPI community blocklist), and GeoLite2
    geo/ASN. Unlimited, matched in memory, always run.

    Tier 2 — per-request APIs, spent only on IPs that earn it. A Tier-1 hit is
    a verdict, not a trigger: feed-listed IPs spend no Tier-2 quota.
      * greynoise: runs when activity crosses TIER2_MIN_EVENTS /
        TIER2_MIN_THREAT_SCORE (scanner-vs-targeted signal).
      * abuseipdb: runs when threat_score >= TIER2_HIGH_THREAT_SCORE AND
        greynoise came back inconclusive — if GreyNoise already classified the
        IP, a second opinion isn't worth the quota.
      * virustotal: same bar, and OFF unless VT_ENABLE=true — VirusTotal's ToS
        forbids commercial use of the free per-request API; bring your own
        licensed key before enabling.

    The worker calls bind(pool) after construction; the pool feeds the activity
    gate (ips.event_count / threat_score) and Tier-1 persistence. Unbound, the
    gate reads 0/0 and Tier 2 never runs."""
    name = "tiered"

    def __init__(self, settings: dict):
        super().__init__(settings)
        from feeds import get_feed_providers
        self.feed_providers = get_feed_providers(settings)
        tier2 = ["greynoise", "abuseipdb"]
        if str(settings.get("VT_ENABLE", "")).lower() in ("1", "true", "yes"):
            tier2.append("virustotal")
        self._tier2 = [_REGISTRY[n](settings) for n in tier2]
        self._min_events = int(settings.get("TIER2_MIN_EVENTS", 10))
        self._min_score = float(settings.get("TIER2_MIN_THREAT_SCORE", 30))
        self._high_score = float(settings.get("TIER2_HIGH_THREAT_SCORE", 60))
        self._pool = None

    def bind(self, pool):
        self._pool = pool

    async def _activity(self, ip: str) -> tuple[int, float]:
        if not self._pool:
            return 0, 0.0
        try:
            async with self._pool.acquire() as con:
                row = await con.fetchrow(
                    "SELECT event_count, threat_score FROM ips WHERE src_ip=$1", ip)
            if row:
                return row["event_count"] or 0, row["threat_score"] or 0.0
        except Exception as ex:
            print(f"[tiered] activity lookup failed for {ip}: {ex}", flush=True)
        return 0, 0.0

    async def enrich(self, ip: str) -> Enrichment:
        named: list[tuple[str, Enrichment | Exception]] = []
        flagged = False
        for fp in self.feed_providers:
            try:
                hit = fp.lookup(ip)
            except Exception as ex:
                named.append((fp.name, ex))
                continue
            if hit:
                named.append((fp.name, hit))
                if _REP_SEVERITY.get(hit.reputation, 0) >= 2:
                    flagged = True

        events, score = await self._activity(ip)
        active = events >= self._min_events or score >= self._min_score
        high = score >= self._high_score

        ran: list[str] = []
        if active:
            gn = next(p for p in self._tier2 if p.name == "greynoise")
            try:
                gn_res: Enrichment | Exception = await gn.enrich(ip)
            except Exception as ex:
                gn_res = ex
            named.append((gn.name, gn_res))
            ran.append(gn.name)
            inconclusive = (isinstance(gn_res, Exception)
                            or gn_res.reputation == "unknown")
            if high and inconclusive:
                paid = [p for p in self._tier2 if p.name != "greynoise"]
                results = await asyncio.gather(
                    *[p.enrich(ip) for p in paid], return_exceptions=True)
                named.extend((p.name, r) for p, r in zip(paid, results))
                ran.extend(p.name for p in paid)

        merged = merge_enrichments(ip, self.name, named)
        merged.raw["tiered"] = {
            "event_count": events, "threat_score": score, "tier1_flagged": flagged,
            "tier2_ran": ran,
            "tier2_reason": "active" if active else "below-threshold",
        }
        return merged
