"""
Provider interface for IP enrichment. This is the seam that makes the intelligence
source swappable: implement enrich(), register the class, set ENRICHMENT_PROVIDER.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional
import httpx


@dataclass
class Enrichment:
    src_ip: str
    provider: str
    country: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    reputation: str = "unknown"            # malicious|suspicious|known|clean|unknown
    confidence: float = 0.0                # 0..1
    categories: list = field(default_factory=list)
    is_known_attacker: bool = False
    raw: dict = field(default_factory=dict)

    def as_db(self):
        return asdict(self)


class EnrichmentProvider:
    name = "base"

    def __init__(self, settings: dict):
        self.settings = settings
        self._http: httpx.AsyncClient | None = None

    def http(self, timeout: float = 10) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=timeout)
        return self._http

    async def enrich(self, ip: str) -> Enrichment:
        raise NotImplementedError


_REGISTRY: dict[str, type[EnrichmentProvider]] = {}


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


def get_provider(name: str, settings: dict) -> EnrichmentProvider:
    if name not in _REGISTRY:
        raise ValueError(f"unknown provider '{name}', have {list(_REGISTRY)}")
    return _REGISTRY[name](settings)
