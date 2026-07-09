"""
Tier-1 bulk feed providers. Unlike EnrichmentProvider (one network call per IP),
a FeedProvider downloads a whole feed on a schedule, persists it in the
feed_indicators Postgres table, and answers lookup() from an in-memory index —
zero per-request quota spent. The worker calls load() once at startup (serve the
last cached copy immediately) and refresh() every FEED_REFRESH_HOURS.

Fail-safe contract: refresh() must never raise past its own logging and must
leave the previous index intact when a download fails.
"""
import ipaddress
import json
import os
import tarfile
import tempfile

import httpx

from base import Enrichment

_FEED_REGISTRY: dict[str, type["FeedProvider"]] = {}


def register_feed(cls):
    _FEED_REGISTRY[cls.name] = cls
    return cls


def get_feed_providers(settings: dict) -> list["FeedProvider"]:
    return [cls(settings) for cls in _FEED_REGISTRY.values()]


class FeedProvider:
    name = "feed-base"

    def __init__(self, settings: dict):
        self.settings = settings

    async def load(self, pool):
        """Populate the in-memory index from feed_indicators (last cached copy)."""

    async def refresh(self, pool):
        """Download the feed, replace this source's rows, rebuild the index."""

    def lookup(self, ip: str) -> Enrichment | None:
        """Pure in-memory match. No network, no DB."""
        raise NotImplementedError


async def _store(pool, source: str, rows: list[tuple]):
    """Atomically replace a source's indicators.
    rows: (indicator_ip, type, category, meta_dict)."""
    records = []
    for ind, typ, cat, meta in rows:
        try:
            records.append((source, ipaddress.ip_address(ind), typ, cat,
                            json.dumps(meta, default=str)))
        except ValueError:
            continue
    async with pool.acquire() as con:
        async with con.transaction():
            await con.execute("DELETE FROM feed_indicators WHERE source=$1", source)
            await con.executemany(
                """INSERT INTO feed_indicators (source, indicator, type, category, meta)
                   VALUES ($1,$2,$3,$4,$5)
                   ON CONFLICT (source, indicator) DO NOTHING""", records)


async def _load_rows(pool, source: str) -> list:
    async with pool.acquire() as con:
        return await con.fetch(
            """SELECT host(indicator) AS ip, category, meta
               FROM feed_indicators WHERE source=$1""", source)


@register_feed
class AbuseChFeodoFeed(FeedProvider):
    """Abuse.ch Feodo Tracker botnet-C2 IP blocklist (CC0, no key needed).
    Narrow but loud: a hit means the IP is active C2 infrastructure."""
    name = "feodo"
    URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._ips: set[str] = set()

    async def load(self, pool):
        self._ips = {r["ip"] for r in await _load_rows(pool, self.name)}
        if self._ips:
            print(f"[feeds] {self.name}: loaded {len(self._ips)} cached IPs", flush=True)

    async def refresh(self, pool):
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
                resp = await c.get(self.URL)
            resp.raise_for_status()
            ips = set()
            for line in resp.text.splitlines():
                line = line.strip()
                if line and line[0] not in "#;":
                    ips.add(line.split()[0])
            if not ips:
                raise ValueError("empty blocklist")
            await _store(pool, self.name, [(ip, "ip", "feodo-c2", {}) for ip in ips])
            self._ips = ips
            print(f"[feeds] {self.name}: refreshed {len(ips)} IPs", flush=True)
        except Exception as ex:
            print(f"[feeds] {self.name}: refresh failed, keeping "
                  f"{len(self._ips)} cached: {ex}", flush=True)

    def lookup(self, ip: str) -> Enrichment | None:
        if ip not in self._ips:
            return None
        e = Enrichment(src_ip=ip, provider=self.name)
        e.reputation = "malicious"
        e.is_known_attacker = True
        e.confidence = 0.9
        e.categories = ["feodo-c2"]
        e.raw = {"source": "feodo-blocklist", "listed": True}
        return e


@register_feed
class AbuseChThreatFoxFeed(FeedProvider):
    """Abuse.ch ThreatFox IOC feed (CC0; API needs a free ABUSECH_KEY).
    Pulls the last 7 days of ip:port IOCs in one call per refresh instead of
    one query per IP. Inactive when no key is configured."""
    name = "threatfox"
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._iocs: dict[str, dict] = {}

    async def load(self, pool):
        self._iocs = {r["ip"]: (json.loads(r["meta"]) if r["meta"] else {})
                      for r in await _load_rows(pool, self.name)}
        if self._iocs:
            print(f"[feeds] {self.name}: loaded {len(self._iocs)} cached IOCs", flush=True)

    async def refresh(self, pool):
        key = self.settings.get("ABUSECH_KEY")
        if not key:
            return
        try:
            async with httpx.AsyncClient(timeout=60) as c:
                resp = await c.post(self.URL, headers={"Auth-Key": key},
                                    json={"query": "get_iocs", "days": 7})
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") != "ok":
                raise ValueError(f"query_status={data.get('query_status')}")
            iocs: dict[str, dict] = {}
            for ioc in data.get("data") or []:
                if ioc.get("ioc_type") != "ip:port":
                    continue
                ip = str(ioc.get("ioc", "")).rsplit(":", 1)[0]
                iocs[ip] = {"malware": ioc.get("malware_printable") or ioc.get("malware"),
                            "threat_type": ioc.get("threat_type"),
                            "confidence_level": ioc.get("confidence_level")}
            await _store(pool, self.name,
                         [(ip, "ip", m.get("malware") or "threatfox-ioc", m)
                          for ip, m in iocs.items()])
            self._iocs = iocs
            print(f"[feeds] {self.name}: refreshed {len(iocs)} IOCs", flush=True)
        except Exception as ex:
            print(f"[feeds] {self.name}: refresh failed, keeping "
                  f"{len(self._iocs)} cached: {ex}", flush=True)

    def lookup(self, ip: str) -> Enrichment | None:
        meta = self._iocs.get(ip)
        if meta is None:
            return None
        e = Enrichment(src_ip=ip, provider=self.name)
        e.reputation = "malicious"
        e.is_known_attacker = True
        e.confidence = min((meta.get("confidence_level") or 75) / 100.0, 1.0)
        cats = [c for c in (meta.get("malware"), meta.get("threat_type")) if c]
        e.categories = cats or ["threatfox-ioc"]
        e.raw = {"source": "threatfox", **meta}
        return e


@register_feed
class CrowdSecLocalFeed(FeedProvider):
    """Decisions from the CrowdSec engine already running in this stack —
    including origin=CAPI, i.e. the ~25k-IP community blocklist the engine pulls
    for free. Local LAPI call, unlimited; needs only CROWDSEC_BOUNCER_KEY."""
    name = "crowdsec-lapi"

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._lapi = settings.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
        self._key = settings.get("CROWDSEC_BOUNCER_KEY", "")
        self._decisions: dict[str, dict] = {}

    async def load(self, pool):
        self._decisions = {r["ip"]: (json.loads(r["meta"]) if r["meta"] else {})
                           for r in await _load_rows(pool, self.name)}
        if self._decisions:
            print(f"[feeds] {self.name}: loaded {len(self._decisions)} cached decisions",
                  flush=True)

    async def refresh(self, pool):
        if not self._key:
            return
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                resp = await c.get(f"{self._lapi}/v1/decisions",
                                   headers={"X-Api-Key": self._key})
            resp.raise_for_status()
            decisions: dict[str, dict] = {}
            for d in resp.json() or []:
                ip = d.get("value")
                if not ip or d.get("type") not in (None, "ban", "captcha"):
                    continue
                entry = decisions.setdefault(ip, {"scenarios": [], "origins": []})
                sc, org = d.get("scenario", ""), d.get("origin", "")
                if sc and sc not in entry["scenarios"]:
                    entry["scenarios"].append(sc)
                if org and org not in entry["origins"]:
                    entry["origins"].append(org)
            await _store(pool, self.name,
                         [(ip, "ip", (m["scenarios"][0] if m["scenarios"] else "ban"), m)
                          for ip, m in decisions.items()])
            self._decisions = decisions
            print(f"[feeds] {self.name}: refreshed {len(decisions)} decisions", flush=True)
        except Exception as ex:
            print(f"[feeds] {self.name}: refresh failed, keeping "
                  f"{len(self._decisions)} cached: {ex}", flush=True)

    def lookup(self, ip: str) -> Enrichment | None:
        meta = self._decisions.get(ip)
        if meta is None:
            return None
        e = Enrichment(src_ip=ip, provider=self.name)
        e.reputation = "malicious"
        e.is_known_attacker = True
        e.confidence = 0.9
        e.categories = [s for s in meta.get("scenarios", []) if s] or ["crowdsec-ban"]
        e.raw = {"source": "crowdsec-lapi", **meta}
        return e


@register_feed
class GeoLiteFeed(FeedProvider):
    """MaxMind GeoLite2 country/ASN lookup from local .mmdb files in GEOIP_DIR.
    Metadata only — fills country/asn/org, never sets a reputation.
    refresh() auto-downloads the databases when MAXMIND_LICENSE_KEY is set
    (GeoLite2 EULA: free, requires a MaxMind account); without a key it serves
    .mmdb files dropped into the volume manually, or stays inactive."""
    name = "geolite"
    _EDITIONS = {"GeoLite2-City": "city", "GeoLite2-ASN": "asn"}
    _DL_URL = ("https://download.maxmind.com/app/geoip_download"
               "?edition_id={edition}&license_key={key}&suffix=tar.gz")

    def __init__(self, settings: dict):
        super().__init__(settings)
        self._dir = settings.get("GEOIP_DIR", "/geoip")
        self._readers: dict[str, object] = {}

    def _open(self):
        try:
            import maxminddb
        except ImportError:
            return
        for edition, kind in self._EDITIONS.items():
            path = os.path.join(self._dir, f"{edition}.mmdb")
            if os.path.exists(path):
                try:
                    self._readers[kind] = maxminddb.open_database(path)
                except Exception as ex:
                    print(f"[feeds] {self.name}: cannot open {path}: {ex}", flush=True)
        if self._readers:
            print(f"[feeds] {self.name}: databases open: "
                  f"{sorted(self._readers)}", flush=True)

    async def load(self, pool):
        self._open()

    async def refresh(self, pool):
        key = self.settings.get("MAXMIND_LICENSE_KEY")
        if not key:
            if not self._readers:
                self._open()
            return
        for edition in self._EDITIONS:
            try:
                url = self._DL_URL.format(edition=edition, key=key)
                async with httpx.AsyncClient(timeout=120, follow_redirects=True) as c:
                    resp = await c.get(url)
                resp.raise_for_status()
                with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmp:
                    tmp.write(resp.content)
                    tmp.flush()
                    with tarfile.open(tmp.name, "r:gz") as tar:
                        member = next(m for m in tar.getmembers()
                                      if m.name.endswith(".mmdb"))
                        member.name = os.path.basename(member.name)
                        tar.extract(member, self._dir)
                print(f"[feeds] {self.name}: downloaded {edition}", flush=True)
            except Exception as ex:
                print(f"[feeds] {self.name}: {edition} download failed: {ex}", flush=True)
        self._open()

    def lookup(self, ip: str) -> Enrichment | None:
        if not self._readers:
            return None
        e = Enrichment(src_ip=ip, provider=self.name)
        got = False
        try:
            city = self._readers.get("city")
            if city:
                rec = city.get(ip) or {}
                iso = (rec.get("country") or {}).get("iso_code")
                if iso:
                    e.country, got = iso, True
            asn = self._readers.get("asn")
            if asn:
                rec = asn.get(ip) or {}
                num = rec.get("autonomous_system_number")
                if num:
                    e.asn, got = str(num), True
                org = rec.get("autonomous_system_organization")
                if org:
                    e.org, got = org, True
        except Exception:
            return None
        return e if got else None
