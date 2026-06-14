"""Scan detector: distinct-port fan-out within a time window => scan."""
import time
from base import Detector, Finding, register


@register
class ScanDetector(Detector):
    key = "scan"

    def __init__(self, settings):
        super().__init__(settings)
        self.threshold = int(settings.get("SCAN_PORT_THRESHOLD", 5))
        self.window_s = int(settings.get("SCAN_WINDOW_SECONDS", 60))
        self._reported: dict[str, float] = {}   # ip -> last report ts (dedupe)

    async def on_event(self, ip, event, window):
        now = time.time()
        recent = [e for e in window if now - e["_recv"] <= self.window_s]
        ports = sorted({int(e["dst_port"]) for e in recent
                        if str(e.get("dst_port", "")).isdigit() and int(e["dst_port"]) > 0})
        if len(ports) < self.threshold:
            return []
        # dedupe: one scan finding per ip per window
        if now - self._reported.get(ip, 0) < self.window_s:
            return []
        self._reported[ip] = now

        services = {e.get("service") for e in recent}
        # vertical: many ports same host (always, single honeypot); classify by spread
        scan_type = "sweep" if len(services) >= 3 else "vertical"
        return [Finding(
            kind="scan", src_ip=ip, scan_type=scan_type, ports=ports,
            detail={"port_count": len(ports), "window_s": self.window_s,
                    "services": sorted(s for s in services if s)},
        )]

    def prune(self, now):
        cutoff = now - self.window_s * 2
        for ip in [ip for ip, t in self._reported.items() if t < cutoff]:
            del self._reported[ip]
