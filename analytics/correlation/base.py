"""
Pluggable detector framework. Add a correlation/behavioral module by subclassing
Detector and decorating with @register; enable it via ENABLED_DETECTORS in .env.
The engine feeds each detector a per-IP sliding window of recent events.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    kind: str                      # "scan" | "attack"
    src_ip: str
    detail: dict = field(default_factory=dict)
    # scan fields
    scan_type: Optional[str] = None
    ports: Optional[list] = None
    # attack fields
    attack_type: Optional[str] = None
    service: Optional[str] = None
    severity: int = 0


class Detector:
    key = "base"

    def __init__(self, settings: dict):
        self.settings = settings

    async def on_event(self, ip: str, event: dict, window: list) -> list[Finding]:
        """window = list of recent event dicts for this ip (oldest..newest)."""
        return []

    def prune(self, now: float) -> None:
        """Drop stale per-IP dedupe state. Override if the detector keeps one."""
        return


_REGISTRY: dict[str, type[Detector]] = {}


def register(cls):
    _REGISTRY[cls.key] = cls
    return cls


def load_detectors(enabled_csv: str, settings: dict) -> list[Detector]:
    wanted = [k.strip() for k in enabled_csv.split(",") if k.strip()]
    out = []
    for k in wanted:
        if k in _REGISTRY:
            out.append(_REGISTRY[k](settings))
    return out
