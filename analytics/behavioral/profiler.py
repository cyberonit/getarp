"""
Behavioral profiler. Maintains a rolling profile per IP and computes a threat score.
The score() method is the documented seam for a future AI/ML module: drop in a model
that consumes the same profile + raw transcripts and return a learned score.
"""
import re
import time

TOOLING_SIGNS = {
    "masscan": re.compile(r"masscan", re.I),
    "hydra": re.compile(r"hydra|medusa|ncrack", re.I),
    "mirai": re.compile(r"/bin/busybox|MIRAI|ECCHI|\.mips|\.arm7", re.I),
    "cryptominer": re.compile(r"xmrig|minerd|stratum\+tcp", re.I),
    "wget_dropper": re.compile(r"(wget|curl)\s+http", re.I),
    "recon": re.compile(r"\b(uname|whoami|cat /etc/passwd|lscpu|free -m)\b", re.I),
}

TACTIC_MAP = {
    "recon": "TA0007-Discovery",
    "wget_dropper": "TA0011-C2/Download",
    "mirai": "TA0002-Execution",
    "cryptominer": "TA0040-Impact",
    "hydra": "TA0006-CredentialAccess",
}


class BehavioralProfiler:
    key = "default"

    def __init__(self, settings: dict):
        self.settings = settings

    def update(self, profile: dict, event: dict) -> dict:
        """Mutate+return a profile dict for one IP given a new event."""
        profile.setdefault("commands_seen", [])
        profile.setdefault("tooling_hints", set())
        profile.setdefault("tactics", set())
        profile.setdefault("services", set())
        profile.setdefault("sessions", set())
        profile.setdefault("event_count", 0)
        profile.setdefault("first", time.time())

        profile["event_count"] += 1
        profile["last"] = time.time()
        if event.get("service"):
            profile["services"].add(event["service"])
        if event.get("session"):
            profile["sessions"].add(event["session"])

        cmd = event.get("command") or ""
        if cmd and event.get("event_type") == "command":
            if cmd not in profile["commands_seen"]:
                profile["commands_seen"].append(cmd[:300])
            for name, rx in TOOLING_SIGNS.items():
                if rx.search(cmd):
                    profile["tooling_hints"].add(name)
                    if name in TACTIC_MAP:
                        profile["tactics"].add(TACTIC_MAP[name])
        return profile

    def score(self, profile: dict) -> float:
        """
        Threat score 0..100. Deterministic heuristic now; AI module can override.
        Weighting: actually executing commands > brute forcing > just probing.
        """
        s = 0.0
        s += min(len(profile.get("services", [])) * 6, 30)        # breadth
        s += min(len(profile.get("commands_seen", [])) * 5, 25)   # interaction depth
        s += min(len(profile.get("tooling_hints", [])) * 12, 36)  # known tooling
        if "mirai" in profile.get("tooling_hints", set()):
            s += 10
        return float(min(round(s, 1), 100.0))

    def classify(self, profile: dict) -> str:
        hints = profile.get("tooling_hints", set())
        if "mirai" in hints or "cryptominer" in hints:
            return "exploiter"
        if profile.get("commands_seen"):
            return "intruder"
        if "hydra" in hints:
            return "bruteforcer"
        if len(profile.get("services", [])) >= 3:
            return "scanner"
        return "prober"

    def snapshot(self, ip: str, profile: dict) -> dict:
        dur = profile.get("last", 0) - profile.get("first", 0)
        return {
            "src_ip": ip,
            "sessions": len(profile.get("sessions", [])),
            "avg_session_s": round(dur / max(len(profile.get("sessions", [])), 1), 1),
            "commands_seen": profile.get("commands_seen", [])[:50],
            "tooling_hints": sorted(profile.get("tooling_hints", set())),
            "tactics": sorted(profile.get("tactics", set())),
            "threat_score": self.score(profile),
            "classification": self.classify(profile),
        }
