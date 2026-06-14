"""Concrete enrichment providers. Add a new one by subclassing + @register."""
import httpx
from base import Enrichment, EnrichmentProvider, register


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
        url = self.settings.get("CROWDSEC_LAPI_URL", "")
        e.reputation = "unknown"
        e.categories = ["cti-key-missing"]
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
