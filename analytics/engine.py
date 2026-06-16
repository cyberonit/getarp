#!/usr/bin/env python3
"""
Analytics engine.

Consumes the canonical `events` stream and runs three jobs concurrently:
  1. correlation   — per-IP sliding window fed to pluggable detectors (scan/attack)
  2. behavioral    — per-IP profile + threat score + classification (AI hook ready)
  3. status (5m)   — snapshot of the live picture, published on redis `status:live`
  4. reports (cron)— daily period summary persisted to `reports`

Everything modular: detectors/profilers are loaded from config so you can add a
"better correlation module" or an AI scorer without editing this file.
"""
import asyncio
import html
import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import asyncpg
import redis.asyncio as redis

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "correlation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "behavioral"))

import scan_detector   # noqa: F401  registers
import attack_detector  # noqa: F401  registers
from base import load_detectors, Finding
from profiler import BehavioralProfiler

EVENTS_STREAM = "events"
GROUP = "analytics"
CONSUMER = os.environ.get("HOSTNAME", "analytics-1")
STATUS_CHANNEL = "status:live"
WINDOW_KEEP_S = 300        # keep 5 min of per-IP events in memory


class Engine:
    def __init__(self, pool, r, settings):
        self.pool = pool
        self.r = r
        self.settings = settings
        self.detectors = load_detectors(
            settings.get("ENABLED_DETECTORS", "scan,attack"), settings)
        self.profiler = BehavioralProfiler(settings)
        self.windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self.profiles: dict[str, dict] = defaultdict(dict)
        print(f"[analytics] detectors = {[d.key for d in self.detectors]}", flush=True)

    # ───────────────── correlation + behavioral ─────────────────
    async def handle_event(self, ev: dict):
        ip = ev.get("src_ip")
        if not ip:
            return
        ev["_recv"] = time.time()
        win = self.windows[ip]
        win.append(ev)
        # trim old
        cutoff = time.time() - WINDOW_KEEP_S
        while win and win[0]["_recv"] < cutoff:
            win.popleft()

        # detectors
        for det in self.detectors:
            try:
                for f in await det.on_event(ip, ev, list(win)):
                    await self.persist_finding(f)
            except Exception as e:
                print(f"[analytics] detector {det.key}: {e}", flush=True)

        # behavioral profile
        prof = self.profiler.update(self.profiles[ip], ev)
        snap = self.profiler.snapshot(ip, prof)
        await self.persist_profile(snap)

    async def persist_finding(self, f: Finding):
        async with self.pool.acquire() as con:
            if f.kind == "scan":
                await con.execute(
                    """INSERT INTO scan_events
                       (src_ip, scan_type, ports, port_count, window_s, detail)
                       VALUES ($1,$2,$3,$4,$5,$6)""",
                    f.src_ip, f.scan_type, f.ports or [], len(f.ports or []),
                    f.detail.get("window_s"), json.dumps(f.detail))
                await con.execute(
                    "UPDATE ips SET classification='scanner', "
                    "threat_score=GREATEST(threat_score,30) WHERE src_ip=$1", f.src_ip)
            elif f.kind == "attack":
                await con.execute(
                    """INSERT INTO attack_events
                       (src_ip, attack_type, service, evidence, severity)
                       VALUES ($1,$2,$3,$4,$5)""",
                    f.src_ip, f.attack_type, f.service,
                    json.dumps(f.detail), f.severity)
                bump = {"exploit": 75, "post_auth_exec": 85,
                        "cred_stuffing": 55, "bruteforce": 45}.get(f.attack_type, 40)
                await con.execute(
                    "UPDATE ips SET threat_score=GREATEST(threat_score,$2) "
                    "WHERE src_ip=$1", f.src_ip, float(bump))
        # push a lightweight live ping so the UI can highlight new attacks
        await self.r.publish(STATUS_CHANNEL, json.dumps(
            {"type": f.kind, "src_ip": f.src_ip,
             "label": f.attack_type or f.scan_type}))

    async def persist_profile(self, snap: dict):
        async with self.pool.acquire() as con:
            await con.execute(
                """INSERT INTO behavior_profiles
                   (src_ip, sessions, avg_session_s, commands_seen, tooling_hints,
                    tactics, threat_score, detail, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
                   ON CONFLICT (src_ip) DO UPDATE SET
                     sessions=$2, avg_session_s=$3, commands_seen=$4,
                     tooling_hints=$5, tactics=$6, threat_score=$7, detail=$8,
                     updated_at=now()""",
                snap["src_ip"], snap["sessions"], snap["avg_session_s"],
                snap["commands_seen"], snap["tooling_hints"], snap["tactics"],
                snap["threat_score"], json.dumps(snap))
            await con.execute(
                "UPDATE ips SET classification=$2, threat_score=GREATEST(threat_score,$3) "
                "WHERE src_ip=$1", snap["src_ip"], snap["classification"],
                snap["threat_score"])

    # ───────────────── consumer loop ─────────────────
    async def consume(self):
        try:
            await self.r.xgroup_create(EVENTS_STREAM, GROUP, id="$", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        while True:
            resp = await self.r.xreadgroup(GROUP, CONSUMER, {EVENTS_STREAM: ">"},
                                           count=100, block=2000)
            if not resp:
                continue
            for _stream, messages in resp:
                for msg_id, fields in messages:
                    try:
                        await self.handle_event(dict(fields))
                    except Exception as e:
                        print(f"[analytics] handle: {e}", flush=True)
                    finally:
                        await self.r.xack(EVENTS_STREAM, GROUP, msg_id)

    # ───────────────── 5-minute status ─────────────────
    async def status_loop(self):
        interval = int(self.settings.get("STATUS_INTERVAL_SECONDS", 300))
        while True:
            try:
                await self.snapshot_status()
            except Exception as e:
                print(f"[analytics] status: {e}", flush=True)
            self.gc_state()
            await asyncio.sleep(interval)

    # ───────────────── periodic memory cleanup ─────────────────
    def gc_state(self):
        """Drop in-memory per-IP state for attackers we haven't heard from in a
        while, so a long-running engine doesn't accumulate one entry per IP
        ever seen across its whole uptime."""
        now = time.time()
        win_cutoff = now - WINDOW_KEEP_S
        stale_windows = [ip for ip, w in self.windows.items()
                         if not w or w[-1]["_recv"] < win_cutoff]
        for ip in stale_windows:
            del self.windows[ip]

        profile_cutoff = now - 86400  # 24h of inactivity
        stale_profiles = [ip for ip, p in self.profiles.items()
                          if p.get("last", 0) < profile_cutoff]
        for ip in stale_profiles:
            del self.profiles[ip]

        for det in self.detectors:
            det.prune(now)

        if stale_windows or stale_profiles:
            print(f"[analytics] gc: dropped {len(stale_windows)} windows, "
                  f"{len(stale_profiles)} profiles", flush=True)

    async def snapshot_status(self):
        async with self.pool.acquire() as con:
            active = await con.fetchval(
                "SELECT count(DISTINCT src_ip) FROM events WHERE ts > now()-interval '5 min'")
            new_ips = await con.fetchval(
                "SELECT count(*) FROM ips WHERE first_seen > now()-interval '5 min'")
            epm = await con.fetchval(
                "SELECT count(*)/5.0 FROM events WHERE ts > now()-interval '5 min'")
            top_ports = await con.fetch(
                """SELECT dst_port, count(*) n FROM events
                   WHERE ts > now()-interval '1 hour' AND dst_port IS NOT NULL
                   GROUP BY dst_port ORDER BY n DESC LIMIT 8""")
            top_services = await con.fetch(
                """SELECT service, count(*) n FROM events
                   WHERE ts > now()-interval '1 hour' AND service IS NOT NULL
                   GROUP BY service ORDER BY n DESC LIMIT 8""")
            top_countries = await con.fetch(
                """SELECT e.country, count(*) n FROM ip_enrichment e
                   JOIN ips i ON i.src_ip=e.src_ip
                   WHERE i.last_seen > now()-interval '1 hour' AND e.country IS NOT NULL
                   GROUP BY e.country ORDER BY n DESC LIMIT 8""")
            attacks_5m = await con.fetchval(
                "SELECT count(*) FROM attack_events WHERE ts > now()-interval '5 min'")

        level = ("critical" if attacks_5m > 50 else "high" if attacks_5m > 15
                 else "elevated" if attacks_5m > 3 else "low")
        snap = {
            "active_attackers": active or 0,
            "new_ips": new_ips or 0,
            "events_per_min": round(float(epm or 0), 1),
            "top_ports": [dict(r) for r in top_ports],
            "top_services": [dict(r) for r in top_services],
            "top_countries": [dict(r) for r in top_countries],
            "threat_level": level,
        }
        async with self.pool.acquire() as con:
            await con.execute(
                """INSERT INTO status_snapshots
                   (active_attackers, new_ips, events_per_min, top_ports,
                    top_services, top_countries, threat_level, detail)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
                snap["active_attackers"], snap["new_ips"], snap["events_per_min"],
                json.dumps(snap["top_ports"]), json.dumps(snap["top_services"]),
                json.dumps(snap["top_countries"]), snap["threat_level"],
                json.dumps(snap))
        await self.r.publish(STATUS_CHANNEL, json.dumps({"type": "status", **snap}))
        print(f"[analytics] status: {level} active={snap['active_attackers']}", flush=True)

    # ───────────────── daily report ─────────────────
    async def report_loop(self):
        hour = int(self.settings.get("REPORT_CRON_HOUR", 6))
        while True:
            now = datetime.now(timezone.utc)
            target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)
            await asyncio.sleep((target - now).total_seconds())
            try:
                await self.build_report("daily", "1 day")
            except Exception as e:
                print(f"[analytics] report: {e}", flush=True)

    async def build_report(self, kind: str, span: str):
        async with self.pool.acquire() as con:
            total = await con.fetchval(
                "SELECT count(*) FROM events WHERE ts > now()-$1::interval", span)
            ips = await con.fetchval(
                "SELECT count(DISTINCT src_ip) FROM events WHERE ts > now()-$1::interval", span)
            scans = await con.fetchval(
                "SELECT count(*) FROM scan_events WHERE ts > now()-$1::interval", span)
            attacks = await con.fetch(
                "SELECT attack_type, count(*) n FROM attack_events "
                "WHERE ts > now()-$1::interval GROUP BY attack_type ORDER BY n DESC", span)
            top = await con.fetch(
                "SELECT i.src_ip, i.threat_score, i.classification, e.country, e.asn, e.org "
                "FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip "
                "WHERE i.last_seen > now()-$1::interval "
                "ORDER BY i.threat_score DESC LIMIT 20", span)
            summary = {
                "events": total, "unique_ips": ips, "scans": scans,
                "attacks_by_type": [dict(r) for r in attacks],
                "top_attackers": [dict(r) for r in top],
            }
            html = self._render_html(kind, summary)
            await con.execute(
                "INSERT INTO reports (period_from, period_to, kind, summary, html) "
                "VALUES (now()-$1::interval, now(), $2, $3, $4)",
                span, kind, json.dumps(summary, default=str), html)
        print(f"[analytics] {kind} report built", flush=True)

    @staticmethod
    def _render_html(kind, s):
        esc = html.escape
        rows = "".join(
            f"<tr><td>{esc(str(a['src_ip']))}</td><td>{esc(str(a.get('threat_score')))}</td>"
            f"<td>{esc(str(a.get('classification')))}</td>"
            f"<td>{esc(str(a.get('country') or '?'))}</td>"
            f"<td>{esc(str(a.get('asn') or '?'))}</td>"
            f"<td>{esc(str(a.get('org') or '?'))}</td></tr>"
            for a in s["top_attackers"])
        atk = "".join(f"<li>{esc(str(a['attack_type']))}: {esc(str(a['n']))}</li>"
                      for a in s["attacks_by_type"])
        return f"""<html><body style="font-family:system-ui">
<h1>getarp.net {esc(kind)} report</h1>
<p>Events: {esc(str(s['events']))} &middot; Unique IPs: {esc(str(s['unique_ips']))} &middot; Scans: {esc(str(s['scans']))}</p>
<h3>Attacks by type</h3><ul>{atk}</ul>
<h3>Top attackers</h3>
<table border=1 cellpadding=4><tr><th>IP</th><th>Score</th><th>Class</th><th>Country</th><th>AS</th><th>Org</th></tr>
{rows}</table></body></html>"""


async def load_settings(pool) -> dict:
    s = dict(os.environ)
    async with pool.acquire() as con:
        for row in await con.fetch("SELECT key, value FROM settings"):
            # DB keys are lowercase; store under both cases so detectors that
            # read UPPER_CASE keys (analytics) and lowercase readers (enrichment)
            # all pick up DB overrides instead of being shadowed by env vars.
            s[row["key"]] = row["value"]
            s[row["key"].upper()] = row["value"]
    return s


async def main():
    dsn = (f'postgresql://{os.environ["PG_USER"]}:{os.environ["PG_PASSWORD"]}'
           f'@{os.environ["PG_HOST"]}:{os.environ["PG_PORT"]}/{os.environ["PG_DB"]}')
    pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
    r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    settings = await load_settings(pool)
    eng = Engine(pool, r, settings)
    await asyncio.gather(eng.consume(), eng.status_loop(), eng.report_loop())


if __name__ == "__main__":
    asyncio.run(main())
