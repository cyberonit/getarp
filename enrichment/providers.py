"""Concrete enrichment providers. Add a new one by subclassing + @register."""
import asyncio
import os
import time
import httpx
from base import Enrichment, EnrichmentProvider, _REGISTRY, register


@register
class CrowdSecProvider(EnrichmentProvider):
    """Periodically pulls all active decisions from the local CrowdSec LAPI and
    does in-memory lookups.  Zero external API calls."""
    name = "crowdsec"
    _TTL = 300

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._lapi = settings.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
        self._key = settings.get("CROWDSEC_BOUNCER_KEY", "")
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

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        if not self._key:
            e.categories = ["bouncer-key-missing"]
            return e
        if time.time() - self._last_fetch >= self._TTL and not self._lock.locked():
            await self._refresh()
        scenarios = self._decisions.get(ip)
        if scenarios:
            e.reputation = "malicious"
            e.is_known_attacker = True
            e.confidence = 0.9
            e.categories = list({s for s in scenarios if s})
        else:
            e.reputation = "unknown"
        e.raw = {"banned": bool(scenarios), "scenarios": scenarios or []}
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

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._cache: dict[str, Enrichment] = {}
        self._cache_ts: dict[str, float] = {}
        self._cache_ttl = 3600
        self._rate_limited_until: float = 0.0

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
                e.reputation = "clean"
                self._cache[ip] = e
                self._cache_ts[ip] = now
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
        self._cache[ip] = e
        self._cache_ts[ip] = now
        return e


@register
class VirusTotalProvider(EnrichmentProvider):
    """VirusTotal IP reputation via the v3 API. Requires a free API key."""
    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/ip_addresses/"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("VIRUSTOTAL_KEY")
        if not key:
            e.categories = ["api-key-missing"]
            return e
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(self.URL + ip, headers={"x-apikey": key})
            if resp.status_code == 404:
                e.reputation = "clean"
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
        return e


@register
class AbusechProvider(EnrichmentProvider):
    """Abuse.ch provider. Uses the ThreatFox API when ABUSECH_KEY is set,
    falls back to the public Feodo Tracker IP blocklist otherwise."""
    name = "abusech"
    _THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    _BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    _CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "feodo_ipblocklist.txt")
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
        if time.time() - self._last_fetch >= self._TTL and not self._lock.locked():
            asyncio.create_task(self._refresh_blocklist())
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
        if time.time() - self._last_fetch >= self._TTL and not self._lock.locked():
            asyncio.create_task(self._refresh_blocklist())
        if ip in self._blacklist:
            e.reputation = "malicious"
            e.is_known_attacker = True
            e.confidence = 0.9
            e.categories = ["feodo-c2"]
        else:
            e.reputation = "unknown"
        return e


_REP_SEVERITY = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


@register
class MultiProvider(EnrichmentProvider):
    """Queries all other registered providers in parallel and merges results.
    Set ENRICHMENT_PROVIDER=multi to activate."""
    name = "multi"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._providers = [cls(settings) for name, cls in _REGISTRY.items()
                           if name != self.name]

    async def enrich(self, ip: str) -> Enrichment:
        providers = self._providers
        results = await asyncio.gather(
            *[p.enrich(ip) for p in providers], return_exceptions=True)

        merged = Enrichment(src_ip=ip, provider=self.name)
        merged.raw = {}

        for p, result in zip(providers, results):
            if isinstance(result, Exception):
                merged.raw[p.name] = {"error": str(result)}
                continue
            merged.raw[p.name] = result.raw

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
