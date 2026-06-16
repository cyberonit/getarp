"""Concrete enrichment providers. Add a new one by subclassing + @register."""
import asyncio
import httpx
from base import Enrichment, EnrichmentProvider, _REGISTRY, register


@register
class CrowdSecProvider(EnrichmentProvider):
    """Uses CrowdSec CTI (api.crowdsec.net). Falls back to local LAPI decisions."""
    name = "crowdsec"
    CTI = "https://cti.api.crowdsec.net/v2/smoke/"

    async def enrich(self, ip: str) -> Enrichment:
        key = self.settings.get("CROWDSEC_CTI_KEY")
        e = Enrichment(src_ip=ip, provider=self.name)
        if not key:
            # no CTI key: at least reflect whether our own LAPI has banned it
            return await self._local(ip, e)
        headers = {"x-api-key": key, "accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.CTI + ip, headers=headers)
            if resp.status_code == 404:
                e.reputation = "clean"
                return e
            resp.raise_for_status()
            d = resp.json()
            e.raw = d
            e.reputation = d.get("reputation", "unknown")
            e.confidence = {"malicious": 0.95, "suspicious": 0.6,
                            "known": 0.4}.get(e.reputation, 0.1)
            e.is_known_attacker = e.reputation in ("malicious", "suspicious")
            loc = d.get("location", {})
            e.country = loc.get("country")
            asn = (d.get("as_name") or "")
            e.asn = str(d.get("as_num") or "")
            e.org = asn
            behaviors = d.get("behaviors", []) or []
            e.categories = [b.get("label", b.get("name", "")) for b in behaviors]
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e

    async def _local(self, ip: str, e: Enrichment) -> Enrichment:
        """Fall back to querying the local LAPI decisions when no CTI key is available."""
        url = self.settings.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
        key = self.settings.get("CROWDSEC_BOUNCER_KEY", "")
        e.reputation = "unknown"
        e.categories = ["cti-key-missing"]
        if not key:
            return e
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                resp = await c.get(f"{url}/v1/decisions",
                                   headers={"X-Api-Key": key},
                                   params={"ip": ip})
            if resp.status_code == 200:
                decisions = resp.json() or []
                if decisions:
                    e.reputation = "malicious"
                    e.is_known_attacker = True
                    e.confidence = 0.9
                    e.categories = list({d.get("scenario", "")
                                         for d in decisions if d.get("scenario")})
        except Exception as ex:
            e.raw = {"error": str(ex)}
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
    name = "greynoise"
    URL = "https://api.greynoise.io/v3/community/"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        key = self.settings.get("GREYNOISE_KEY")
        headers = {"key": key} if key else {}
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                resp = await c.get(self.URL + ip, headers=headers)
            if resp.status_code == 404:
                e.reputation = "clean"
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
class CiscoTalosProvider(EnrichmentProvider):
    """Cisco Talos IP reputation. No API key required."""
    name = "ciscotalos"
    URL = "https://talosintelligence.com/sb_api/host_info"

    async def enrich(self, ip: str) -> Enrichment:
        e = Enrichment(src_ip=ip, provider=self.name)
        try:
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Referer": "https://talosintelligence.com/reputation_center",
            }
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(self.URL, params={"url": ip}, headers=headers)
            resp.raise_for_status()
            d = resp.json()
            e.raw = d
            rep = (d.get("reputation") or d.get("web_score_name") or "").lower()
            e.reputation = {"poor": "malicious", "untrusted": "malicious",
                            "neutral": "unknown", "good": "clean"}.get(rep, "unknown")
            e.is_known_attacker = rep in ("poor", "untrusted")
            e.confidence = {"poor": 0.85, "untrusted": 0.95,
                            "neutral": 0.3, "good": 0.0}.get(rep, 0.1)
            e.categories = [rep] if rep else []
        except Exception as ex:
            e.raw = {"error": str(ex)}
        return e


_REP_SEVERITY = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}


@register
class MultiProvider(EnrichmentProvider):
    """Queries all other registered providers in parallel and merges results.
    Set ENRICHMENT_PROVIDER=multi to activate."""
    name = "multi"

    def __init__(self, settings: dict):
        super().__init__(settings)
        # Cache provider instances at init time — _REGISTRY is fully populated by
        # the time this runs (all classes in this module are already decorated).
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

            # most severe reputation wins
            if _REP_SEVERITY.get(result.reputation, 0) > _REP_SEVERITY.get(merged.reputation, 0):
                merged.reputation = result.reputation

            # highest confidence wins
            if result.confidence > merged.confidence:
                merged.confidence = result.confidence

            # any provider flagging as attacker is enough
            if result.is_known_attacker:
                merged.is_known_attacker = True

            # first non-null geo/ASN wins
            if not merged.country and result.country:
                merged.country = result.country
            if not merged.asn and result.asn:
                merged.asn = result.asn
            if not merged.org and result.org:
                merged.org = result.org

            # union of all categories
            for cat in result.categories:
                if cat and cat not in merged.categories:
                    merged.categories.append(cat)

        return merged
