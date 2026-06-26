"""
Behavioral profiler. Maintains a rolling profile per IP and computes a threat score.
The score() method is the documented seam for a future AI/ML module: drop in a model
that consumes the same profile + raw transcripts and return a learned score.
"""
import re
import time

TOOLING_SIGNS = {
    "masscan": re.compile(r"masscan", re.I),
    # hydra/medusa/ncrack show up in SSH client version banners as well as commands
    "hydra": re.compile(r"hydra|medusa|ncrack|libssh(?!-utils)", re.I),
    "mirai": re.compile(r"/bin/busybox|MIRAI|ECCHI|\.mips|\.arm7", re.I),
    "cryptominer": re.compile(r"xmrig|minerd|stratum\+tcp", re.I),
    "wget_dropper": re.compile(r"(wget|curl)\s+http", re.I),
    # SSH post-auth recon: expanded beyond telnet-era commands
    "recon": re.compile(
        r"\b(uname|whoami|id|hostname|ifconfig|ip\s+addr|netstat|ps\s+aux"
        r"|cat\s+/etc/passwd|cat\s+/etc/shadow|lscpu|free\s+-m"
        r"|ls\s+/home|ls\s+/root|ls\s+/tmp)\b", re.I),
    # persistence mechanisms common after SSH login
    "persistence": re.compile(
        r"authorized_keys|crontab|/etc/cron|/etc/rc\.local"
        r"|\.bashrc|\.profile|/etc/profile", re.I),
    # privilege escalation attempts
    "privesc": re.compile(
        r"chmod\s+[+]s|chmod\s+4[0-9]{3}|sudo\s|su\s+root|passwd\s+root|chown\s+root", re.I),
    # pipe-to-shell droppers and reverse shells (complements wget_dropper)
    "shell_dropper": re.compile(
        r"curl\s+.+\|\s*(ba)?sh|wget\s+.+-O\s*-\s*\|\s*(ba)?sh"
        r"|python\s+-c|perl\s+-e|bash\s+-i\s*>&|/dev/tcp/|nc\s+-e|ncat\s+-e", re.I),
    # log/history wiping
    "cleanup": re.compile(
        r"history\s+-c|unset\s+HISTFILE|HISTSIZE=0"
        r"|rm\s+.*\.bash_history|rm\s+-rf\s+/var/log", re.I),
}

TACTIC_MAP = {
    "recon": "TA0007-Discovery",
    "wget_dropper": "TA0011-C2/Download",
    "shell_dropper": "TA0011-C2/Download",
    "mirai": "TA0002-Execution",
    "cryptominer": "TA0040-Impact",
    "hydra": "TA0006-CredentialAccess",
    "persistence": "TA0003-Persistence",
    "privesc": "TA0004-PrivEscalation",
    "cleanup": "TA0005-DefenseEvasion",
}

BRUTEFORCE_TACTIC_THRESHOLD = 5  # login attempts before we flag TA0006


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
        profile.setdefault("login_attempts", 0)
        profile.setdefault("first", time.time())

        profile["event_count"] += 1
        profile["last"] = time.time()
        et = event.get("event_type")
        if event.get("service"):
            profile["services"].add(event["service"])
        if event.get("session"):
            profile["sessions"].add(event["session"])

        # credential access: track login attempts and map to MITRE tactic
        if et in ("login_attempt", "login_success"):
            profile["login_attempts"] += 1
            if profile["login_attempts"] >= BRUTEFORCE_TACTIC_THRESHOLD:
                profile["tactics"].add("TA0006-CredentialAccess")
            if et == "login_success":
                profile["tactics"].add("TA0001-InitialAccess")

        # tooling detection: scan commands (post-auth) and SSH client banners (signature)
        text_fields = []
        if et == "command":
            cmd = event.get("command") or ""
            if cmd:
                if cmd not in profile["commands_seen"] and len(profile["commands_seen"]) < 200:
                    profile["commands_seen"].append(cmd[:300])
                text_fields.append(cmd)
        sig = event.get("signature") or ""
        if sig:
            text_fields.append(sig)

        for text in text_fields:
            for name, rx in TOOLING_SIGNS.items():
                if rx.search(text):
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
        s += min(profile.get("login_attempts", 0) * 1.5, 20)      # credential attacks
        if "mirai" in profile.get("tooling_hints", set()):
            s += 10
        return float(min(round(s, 1), 100.0))

    def classify(self, profile: dict) -> str:
        hints = profile.get("tooling_hints", set())
        if "mirai" in hints or "cryptominer" in hints:
            return "exploiter"
        if profile.get("commands_seen"):
            return "intruder"
        if "hydra" in hints or profile.get("login_attempts", 0) >= BRUTEFORCE_TACTIC_THRESHOLD:
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
            "login_attempts": profile.get("login_attempts", 0),
            "commands_seen": profile.get("commands_seen", [])[:50],
            "tooling_hints": sorted(profile.get("tooling_hints", set())),
            "tactics": sorted(profile.get("tactics", set())),
            "threat_score": self.score(profile),
            "classification": self.classify(profile),
        }
