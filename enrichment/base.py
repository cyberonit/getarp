"""
Provider interface for IP enrichment. This is the seam that makes the intelligence
source swappable: implement enrich(), register the class, set ENRICHMENT_PROVIDER.
"""
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

import httpx


# ───────────────────────── HTTP timeouts ─────────────────────────
# Every outbound call in this image goes through http_timeout(). A scalar
# httpx timeout applies one value to all four phases, which is never quite
# right: connecting to a black-holed host should fail in seconds, while a bulk
# feed download legitimately runs for minutes. Splitting them means a slow feed
# is not cancelled mid-download and a dead provider cannot occupy the worker
# for a minute per IP.
#
# Note what a read timeout does and does not bound: it limits the wait between
# bytes, not the total call, so a server dribbling a response can still hold a
# connection open. That is acceptable for the feed downloads (they make
# progress) and bounded for per-IP lookups by the response sizes involved.
HTTP_CONNECT_TIMEOUT_S = float(os.environ.get("HTTP_CONNECT_TIMEOUT_S") or 5.0)
HTTP_READ_TIMEOUT_S = float(os.environ.get("HTTP_READ_TIMEOUT_S") or 15.0)


def http_timeout(read: Optional[float] = None) -> httpx.Timeout:
    """Per-phase timeouts for an AsyncClient. `read` overrides the default for
    calls that are expected to be slow (bulk feed downloads)."""
    read_s = HTTP_READ_TIMEOUT_S if read is None else float(read)
    return httpx.Timeout(connect=HTTP_CONNECT_TIMEOUT_S, read=read_s,
                         write=read_s, pool=HTTP_CONNECT_TIMEOUT_S)


# Postgres stores NUL (U+0000) in neither text nor jsonb: a text column rejects
# the raw byte, and jsonb rejects the escaped form json.dumps emits. Provider
# responses are third-party data we do not control — org/hostname/category
# strings can be derived from attacker-influenced rDNS or WHOIS — and the whole
# provider payload lands in ip_enrichment.raw (JSONB). worker.consume() catches
# the failure, logs it and ACKs the message, so a NUL would silently leave that
# IP permanently unenriched: no country, no ASN, no is_known_attacker.
#
# KEEP IN SYNC with pipeline/ingestor.py _strip_nulls — separate images, so it
# cannot be shared as a module (same constraint as the report-HTML renderers in
# analytics/engine.py and api/routers/admin.py).
NUL_REPLACEMENT = "�"


def _strip_nulls(value):
    """Recursively replace NUL characters in any string within value."""
    if isinstance(value, str):
        return value.replace("\x00", NUL_REPLACEMENT) if "\x00" in value else value
    if isinstance(value, dict):
        return {_strip_nulls(k): _strip_nulls(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_nulls(v) for v in value]
    return value


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
        # Sanitized at the dataclass -> database boundary so every provider is
        # covered by construction, rather than each call site remembering.
        return _strip_nulls(asdict(self))


class EnrichmentProvider:
    name = "base"

    def __init__(self, settings: dict):
        self.settings = settings

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
