"""
Attack detector: brute force, post-auth command execution, and IDS exploit sigs.
Each is a distinct attack_type so the dashboard can break them out.
"""
import time
from base import Detector, Finding, register


@register
class AttackDetector(Detector):
    key = "attack"

    def __init__(self, settings):
        super().__init__(settings)
        self.bf_threshold = int(settings.get("BRUTEFORCE_THRESHOLD", 10))
        self.bf_window = int(settings.get("BRUTEFORCE_WINDOW_SECONDS", 120))
        self._reported: dict[str, float] = {}

    async def on_event(self, ip, event, window):
        findings = []
        et = event.get("event_type")
        now = time.time()

        # 1) brute force: many login_attempts in window
        if et in ("login_attempt", "login_success"):
            recent_logins = [e for e in window
                             if e.get("event_type") in ("login_attempt", "login_success")
                             and now - e["_recv"] <= self.bf_window]
            if len(recent_logins) >= self.bf_threshold and not self._dup(ip, "bf", now):
                creds = [(e.get("username"), e.get("password")) for e in recent_logins]
                services = {e.get("service") for e in recent_logins}
                atype = "cred_stuffing" if len({c[0] for c in creds}) > 3 else "bruteforce"
                findings.append(Finding(
                    kind="attack", src_ip=ip, attack_type=atype,
                    service=",".join(s for s in services if s), severity=2,
                    detail={"attempts": len(recent_logins),
                            "distinct_users": len({c[0] for c in creds}),
                            "sample_creds": creds[:10]},
                ))

        # 2) post-auth command execution (attacker got "in" and ran commands)
        if et == "command" and event.get("command"):
            findings.append(Finding(
                kind="attack", src_ip=ip, attack_type="post_auth_exec",
                service=event.get("service"), severity=3,
                detail={"command": event.get("command")[:500]},
            ))

        # 3) IDS exploit signature from Suricata
        if et == "alert" and event.get("signature"):
            sev = int(event.get("severity") or 2)
            findings.append(Finding(
                kind="attack", src_ip=ip, attack_type="exploit",
                service=event.get("service"), severity=max(2, 4 - sev),
                detail={"signature": event.get("signature")},
            ))
        return findings

    def _dup(self, ip, tag, now):
        key = f"{ip}:{tag}"
        if now - self._reported.get(key, 0) < self.bf_window:
            return True
        self._reported[key] = now
        return False

    def prune(self, now):
        cutoff = now - self.bf_window * 2
        for key in [k for k, t in self._reported.items() if t < cutoff]:
            del self._reported[key]
