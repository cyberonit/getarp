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
import contextlib
import html
import json
import os
import signal
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx
import redis.asyncio as redis

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "correlation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "behavioral"))

import heartbeat
import retry
import scan_detector   # noqa: F401  registers
import attack_detector  # noqa: F401  registers
from base import load_detectors, Finding
from profiler import BehavioralProfiler

EVENTS_STREAM = "events"
GROUP = "analytics"
CONSUMER = os.environ.get("HOSTNAME", "analytics-1")
STATUS_CHANNEL = "status:live"
WINDOW_KEEP_S = 300        # keep 5 min of per-IP events in memory
PROFILE_FLUSH_S = 5        # batch profile writes instead of one per event

# ───────────────────────── memory ceilings ─────────────────────────
# The per-IP state below is the engine's memory profile, and both dimensions
# used to be unbounded between garbage collections: any number of IPs, each
# with a 2000-event deque. Events arrive off the stream with their raw payload
# already stripped but a Suricata alert still runs to a kilobyte or so, which
# put one busy scanner at ~2 MB and a few hundred concurrent sources well past
# the container limit — and gc_state() only runs on the 5-minute status tick,
# so a burst has five minutes to do damage.
#
# The caps trade analytic depth for a hard ceiling: 500 events is far more than
# any detector's window (the widest is 60s of ports), and evicting the
# least-recently-seen IP loses in-flight correlation for the quietest source
# rather than the loudest.
WINDOW_MAX_EVENTS = int(os.environ.get("WINDOW_MAX_EVENTS") or 500)
WINDOW_MAX_IPS = int(os.environ.get("WINDOW_MAX_IPS") or 5000)
PROFILE_MAX_IPS = int(os.environ.get("PROFILE_MAX_IPS") or 20000)

REDIS_SOCKET_TIMEOUT_S = float(os.environ.get("REDIS_SOCKET_TIMEOUT_S") or 30.0)
REDIS_CONNECT_TIMEOUT_S = float(os.environ.get("REDIS_CONNECT_TIMEOUT_S") or 10.0)
PG_COMMAND_TIMEOUT_S = float(os.environ.get("PG_COMMAND_TIMEOUT_S") or 60.0)
PG_CONNECT_TIMEOUT_S = float(os.environ.get("PG_CONNECT_TIMEOUT_S") or 10.0)

# Liveness thresholds, one per concurrent loop — see heartbeat.py. The status
# loop's threshold is necessarily the loosest of the three workers: it ticks
# once every STATUS_INTERVAL_SECONDS (300 by default), so anything under two
# intervals plus the time its queries take would restart a perfectly healthy
# engine. The consume and flush loops iterate on the order of seconds and are
# held to much tighter bounds.
_STATUS_INTERVAL_S = float(os.environ.get("STATUS_INTERVAL_SECONDS") or 300)
HEARTBEATS = {
    "consume": heartbeat.env_seconds("ANALYTICS_CONSUME_STALE_S", 120),
    "flush": heartbeat.env_seconds("ANALYTICS_FLUSH_STALE_S", 120),
    "status": heartbeat.env_seconds("ANALYTICS_STATUS_STALE_S",
                                    _STATUS_INTERVAL_S * 2 + 120),
}

# Classification severity, least to most severe. Persisted classifications only
# ever escalate: in-memory profiles are lost on restart / after 24h idle, and a
# returning attacker's fresh (low) classification must not clobber history.
CLASS_RANK = ["unknown", "prober", "scanner", "bruteforcer", "intruder", "exploiter"]
_ESCALATE_CLASS_SQL = (
    "CASE WHEN COALESCE(array_position($4::text[], $2), 0)"
    "       >= COALESCE(array_position($4::text[], classification), 0)"
    " THEN $2 ELSE classification END"
)


class Engine:
    def __init__(self, pool, r, settings):
        self.pool = pool
        self.r = r
        self.settings = settings
        self.detectors = load_detectors(
            settings.get("ENABLED_DETECTORS", "scan,attack"), settings)
        self.profiler = BehavioralProfiler(settings)
        self.windows: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=WINDOW_MAX_EVENTS))
        self.profiles: dict[str, dict] = defaultdict(dict)
        self._dirty: set[str] = set()   # IPs whose profile needs persisting
        print(f"[analytics] detectors = {[d.key for d in self.detectors]}", flush=True)

    # ───────────────── correlation + behavioral ─────────────────
    async def handle_event(self, ev: dict):
        ip = ev.get("src_ip")
        if not ip:
            return
        ev["_recv"] = time.time()
        if ip not in self.windows and len(self.windows) >= WINDOW_MAX_IPS:
            # Over the cap between collections. Evict the least recently seen
            # source rather than refusing the new one: the IP still being
            # talked about is the one worth correlating.
            self._evict_windows()
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
                print(f"[analytics] detector {det.key}: {str(e).replace(chr(10), ' ').replace(chr(13), '')}", flush=True)

        # behavioral profile — persisted in batches by flush_profiles_loop to
        # avoid two DB writes per event during brute-force floods
        if ip not in self.profiles and len(self.profiles) >= PROFILE_MAX_IPS:
            self._evict_profiles()
        self.profiler.update(self.profiles[ip], ev)
        self._dirty.add(ip)

    def _evict_windows(self):
        """Drop the coldest tenth of the correlation windows. Called when a
        flood pushes the tracked-IP count past WINDOW_MAX_IPS between the
        5-minute gc ticks; a tenth at a time keeps this from running on every
        event once the cap is reached."""
        by_age = sorted(self.windows.items(),
                        key=lambda kv: kv[1][-1]["_recv"] if kv[1] else 0)
        for ip, _win in by_age[:max(1, WINDOW_MAX_IPS // 10)]:
            del self.windows[ip]

    def _evict_profiles(self):
        """Same idea for behavioural profiles, which are otherwise held for a
        full 24h of inactivity. A profile evicted early is not lost work: it
        has already been persisted by flush_profiles_loop, and persist_profile
        merges rather than overwrites, so the row keeps accumulating if the IP
        comes back."""
        by_age = sorted(self.profiles.items(),
                        key=lambda kv: kv[1].get("last", 0))
        for ip, _prof in by_age[:max(1, PROFILE_MAX_IPS // 10)]:
            del self.profiles[ip]
            self._dirty.discard(ip)

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
                    f"UPDATE ips SET classification={_ESCALATE_CLASS_SQL}, "
                    "threat_score=GREATEST(threat_score,$3) WHERE src_ip=$1",
                    f.src_ip, "scanner", 30.0, CLASS_RANK)
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
        # Merge, never overwrite: the in-memory profile restarts from zero after
        # an engine restart or 24h-idle gc, so a plain upsert would regress
        # sessions/commands/scores accumulated in earlier runs.
        async with self.pool.acquire() as con:
            await con.execute(
                """INSERT INTO behavior_profiles
                   (src_ip, sessions, avg_session_s, commands_seen, tooling_hints,
                    tactics, threat_score, detail, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
                   ON CONFLICT (src_ip) DO UPDATE SET
                     sessions      = GREATEST(behavior_profiles.sessions, EXCLUDED.sessions),
                     avg_session_s = EXCLUDED.avg_session_s,
                     commands_seen = ARRAY(SELECT DISTINCT c FROM unnest(
                                       behavior_profiles.commands_seen || EXCLUDED.commands_seen) AS c
                                       LIMIT 200),
                     tooling_hints = ARRAY(SELECT DISTINCT t FROM unnest(
                                       behavior_profiles.tooling_hints || EXCLUDED.tooling_hints) AS t),
                     tactics       = ARRAY(SELECT DISTINCT t FROM unnest(
                                       behavior_profiles.tactics || EXCLUDED.tactics) AS t),
                     threat_score  = GREATEST(behavior_profiles.threat_score, EXCLUDED.threat_score),
                     -- detail is a snapshot blob; the API only reads
                     -- login_attempts and classification from it, so merge those
                     detail        = behavior_profiles.detail || EXCLUDED.detail || jsonb_build_object(
                       'login_attempts', GREATEST(
                           COALESCE((behavior_profiles.detail->>'login_attempts')::int, 0),
                           COALESCE((EXCLUDED.detail->>'login_attempts')::int, 0)),
                       'classification', CASE
                           WHEN COALESCE(array_position($9::text[], EXCLUDED.detail->>'classification'), 0)
                             >= COALESCE(array_position($9::text[], behavior_profiles.detail->>'classification'), 0)
                           THEN EXCLUDED.detail->>'classification'
                           ELSE behavior_profiles.detail->>'classification' END),
                     updated_at    = now()""",
                snap["src_ip"], snap["sessions"], snap["avg_session_s"],
                snap["commands_seen"], snap["tooling_hints"], snap["tactics"],
                snap["threat_score"], json.dumps(snap), CLASS_RANK)
            await con.execute(
                f"UPDATE ips SET classification={_ESCALATE_CLASS_SQL}, "
                "threat_score=GREATEST(threat_score,$3) WHERE src_ip=$1",
                snap["src_ip"], snap["classification"], snap["threat_score"],
                CLASS_RANK)

    # ───────────────── batched profile persistence ─────────────────
    async def flush_profiles_loop(self):
        while True:
            await asyncio.sleep(PROFILE_FLUSH_S)
            heartbeat.beat("flush")
            await self.flush_profiles()

    async def flush_profiles(self):
        dirty, self._dirty = self._dirty, set()
        for ip in dirty:
            prof = self.profiles.get(ip)
            if not prof:
                continue
            try:
                await self.persist_profile(self.profiler.snapshot(ip, prof))
            except Exception as e:
                print(f"[analytics] profile flush {ip}: {retry.oneline(e)}",
                      flush=True)
                # Only worth another go if the failure was the database being
                # briefly unavailable; a rejected snapshot would fail the same
                # way for ever and re-queueing it would pin the IP in memory.
                if retry.is_transient(e):
                    self._dirty.add(ip)
            heartbeat.beat("flush")

    # ───────────────── consumer loop ─────────────────
    async def ensure_group(self):
        try:
            await self.r.xgroup_create(EVENTS_STREAM, GROUP, id="$", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def consume(self, stop=None):
        """Read the events stream forever.

        The outer try is what keeps a Redis restart from ending the engine:
        xreadgroup raising used to kill this coroutine, and the gather in main()
        then took the process down with it. Per-event failures stay per-event —
        one detector tripping over one malformed field must not cost the
        remaining events in the batch.
        """
        await self.ensure_group()
        attempt = 0
        while True:
            if stop is not None and stop.is_set():
                return
            try:
                resp = await self.r.xreadgroup(GROUP, CONSUMER,
                                               {EVENTS_STREAM: ">"},
                                               count=100, block=2000)
            except Exception as e:
                attempt += 1
                heartbeat.beat("consume")
                waited = await retry.sleep(attempt)
                print(f"[analytics] stream read failed ({retry.oneline(e)}) — "
                      f"reconnecting, attempt {attempt} in {waited:.1f}s",
                      flush=True)
                # The group goes with the stream if Redis is flushed or evicts
                # it; without recreating it every later read fails identically.
                with contextlib.suppress(Exception):
                    await self.ensure_group()
                continue
            attempt = 0
            heartbeat.beat("consume")
            if not resp:
                continue
            for _stream, messages in resp:
                for msg_id, fields in messages:
                    try:
                        await self.handle_event(dict(fields))
                    except Exception as e:
                        print(f"[analytics] handle "
                              f"[{fields.get('sensor')} {fields.get('src_ip')} "
                              f"{fields.get('event_type')}]: {retry.oneline(e)}",
                              flush=True)
                    finally:
                        # ACK regardless: analytics is a live view, and an event
                        # that cannot be processed now will not process later
                        # either — leaving it pending would just grow the list.
                        with contextlib.suppress(Exception):
                            await self.r.xack(EVENTS_STREAM, GROUP, msg_id)
                heartbeat.beat("consume")

    # ───────────────── 5-minute status ─────────────────
    async def status_loop(self):
        interval = int(self.settings.get("STATUS_INTERVAL_SECONDS", 300))
        while True:
            heartbeat.beat("status")
            try:
                await self.snapshot_status()
            except Exception as e:
                print(f"[analytics] status: {retry.oneline(e)}", flush=True)
            try:
                self.gc_state()
            except Exception as e:
                # gc is bookkeeping; losing a pass costs memory, not data, and
                # must never take the status loop with it.
                print(f"[analytics] gc: {retry.oneline(e)}", flush=True)
            heartbeat.beat("status")
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

    # ───────────────── retention cleanup for non-hypertables ─────────────────
    # Two horizons, because the tables carry very different data.
    #
    # RAW_RETENTION covers everything holding third-party PII — attacker
    # usernames, passwords and commands — and matches the 1-year hypertable
    # retention policies in db/init.sql. Deleting from ips cascades to
    # ip_enrichment (FK ON DELETE CASCADE).
    #
    # AGGREGATE_RETENTION covers `reports`, which holds only the daily rollups
    # (no raw attacker input). At ~4.6 kB per report that is ~1.7 MB/year, so
    # keeping analytical history well past the raw data costs effectively
    # nothing and means shortening RAW_RETENTION is a pure privacy win rather
    # than a trade against trend history.
    RAW_RETENTION = "1 year"
    AGGREGATE_RETENTION = "3 years"

    async def retention_loop(self):
        while True:
            await asyncio.sleep(86400)
            try:
                async with self.pool.acquire() as con:
                    await con.execute(
                        f"DELETE FROM scan_events WHERE ts < now() - interval '{self.RAW_RETENTION}'")
                    await con.execute(
                        f"DELETE FROM attack_events WHERE ts < now() - interval '{self.RAW_RETENTION}'")
                    await con.execute(
                        f"DELETE FROM behavior_profiles WHERE updated_at < now() - interval '{self.RAW_RETENTION}'")
                    await con.execute(
                        f"DELETE FROM ips WHERE last_seen < now() - interval '{self.RAW_RETENTION}'")
                    await con.execute(
                        f"DELETE FROM reports WHERE created_at < now() - interval '{self.AGGREGATE_RETENTION}'")
                print("[analytics] retention cleanup done", flush=True)
            except Exception as e:
                print(f"[analytics] retention: {e}", flush=True)

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

    async def _blocked_ips_count(self, span: str) -> int:
        async with self.pool.acquire() as con:
            return await con.fetchval(
                f"SELECT count(*) FROM ip_enrichment e JOIN ips i ON i.src_ip = e.src_ip "
                f"WHERE e.is_known_attacker = true AND i.last_seen > now() - interval '{span}'")

    async def build_report(self, kind: str, span: str):
        # asyncpg can't bind strings as interval; span is an internal constant
        # (never user input), so it's safe to inline as a literal.
        blocked = await self._blocked_ips_count(span)
        async with self.pool.acquire() as con:
            total = await con.fetchval(
                f"SELECT count(*) FROM events WHERE ts > now() - interval '{span}'")
            ips = await con.fetchval(
                f"SELECT count(DISTINCT src_ip) FROM events WHERE ts > now() - interval '{span}'")
            # first_seen (not last_seen) so this counts hosts genuinely new to
            # getarp, not just active — distinct from unique_ips above, which
            # includes recurring scanners re-hitting the honeypot.
            new_ips = await con.fetchval(
                f"SELECT count(*) FROM ips WHERE first_seen > now() - interval '{span}'")
            scans = await con.fetchval(
                f"SELECT count(*) FROM ips WHERE classification IN ('scanner','prober') "
                f"AND last_seen > now() - interval '{span}'")
            attacks = await con.fetch(
                f"SELECT attack_type, count(*) n FROM attack_events "
                f"WHERE ts > now() - interval '{span}' GROUP BY attack_type ORDER BY n DESC")
            top = await con.fetch(
                f"SELECT i.src_ip, i.threat_score, i.classification, e.country, e.asn, e.org "
                f"FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip "
                f"WHERE i.last_seen > now() - interval '{span}' "
                f"ORDER BY i.threat_score DESC LIMIT 20")
            summary = {
                "events": total, "unique_ips": ips, "new_ips": new_ips, "scans": scans,
                "blocked_ips": blocked,
                "attacks_by_type": [dict(r) for r in attacks],
                "top_attackers": [dict(r) for r in top],
            }
            html = self._render_html(kind, summary)
            await con.execute(
                f"INSERT INTO reports (period_from, period_to, kind, summary, html) "
                f"VALUES (now() - interval '{span}', now(), $1, $2, $3)",
                kind, json.dumps(summary, default=str), html)
        print(f"[analytics] {kind} report built", flush=True)

    @staticmethod
    def _render_html(kind, s):
        # KEEP IN SYNC with api/routers/admin.py _render_report_html (used for
        # regenerating existing reports); separate images, can't share a module.
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
<p>Events: {esc(str(s['events']))} &middot; Unique IPs: {esc(str(s['unique_ips']))} &middot; New IPs: {esc(str(s.get('new_ips', 0)))} &middot; Scans: {esc(str(s['scans']))} &middot; IPs blocked: {esc(str(s.get('blocked_ips', 0)))}</p>
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


def _db_creds():
    svc_pw = os.environ.get("SVC_DB_PASSWORD", "")
    if svc_pw:
        return os.environ.get("SVC_DB_USER", os.environ["PG_USER"]), svc_pw
    return os.environ["PG_USER"], os.environ["PG_PASSWORD"]


async def _connect_pool():
    """Wait for Postgres rather than dying on it — a database restart must not
    take the engine with it and leave the restart policy racing the same window
    on the way back up."""
    user, password = _db_creds()
    attempt = 0
    while True:
        try:
            return await asyncpg.create_pool(
                host=os.environ["PG_HOST"],
                port=int(os.environ["PG_PORT"]),
                database=os.environ["PG_DB"],
                user=user,
                password=password,
                min_size=2, max_size=10,
                # The report and retention queries are the slowest in the
                # system, hence the roomier default here — but unbounded is not
                # an option: one wedged query holds its connection, and ten of
                # them leave every acquire() waiting behind a process that
                # still looks perfectly alive.
                command_timeout=PG_COMMAND_TIMEOUT_S,
                timeout=PG_CONNECT_TIMEOUT_S,
            )
        except Exception as ex:
            attempt += 1
            waited = await retry.sleep(attempt)
            print(f"[analytics] postgres unavailable ({retry.oneline(ex)}) — "
                  f"retry {attempt} in {waited:.1f}s", flush=True)


def _redis_client():
    """Redis with socket timeouts. The default client has none: against a peer
    that is gone but whose TCP connection was never torn down, the blocking
    XREADGROUP in consume() waits for ever — process alive, no CPU, no logs, no
    restart. try/except cannot catch a call that never returns."""
    return redis.from_url(
        os.environ["REDIS_URL"], decode_responses=True,
        # Must exceed the 2s XREADGROUP block, or every idle read is an error.
        socket_timeout=REDIS_SOCKET_TIMEOUT_S,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_S,
        socket_keepalive=True,
        health_check_interval=30,
        retry_on_timeout=True,
    )


async def main():
    heartbeat.start(HEARTBEATS)
    pool = await _connect_pool()
    r = _redis_client()
    settings = await load_settings(pool)
    eng = Engine(pool, r, settings)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    consumer = asyncio.create_task(eng.consume(stop))
    others = [asyncio.create_task(eng.flush_profiles_loop()),
              asyncio.create_task(eng.status_loop()),
              asyncio.create_task(eng.report_loop()),
              asyncio.create_task(eng.retention_loop()),
              asyncio.create_task(heartbeat.watchdog(HEARTBEATS))]

    stopper = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait([consumer, *others, stopper],
                                 return_when=asyncio.FIRST_COMPLETED)
    if stopper not in done:
        for task in done:
            if not task.cancelled() and task.exception():
                print(f"[analytics] loop exited unexpectedly: "
                      f"{retry.oneline(task.exception())}", flush=True)

    print("[analytics] stopping — flushing profiles", flush=True)
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(consumer), timeout=10)
    for task in (consumer, *others, stopper):
        task.cancel()
    await asyncio.gather(consumer, *others, stopper, return_exceptions=True)
    # Profiles are only written every PROFILE_FLUSH_S, so up to five seconds of
    # accumulated sessions, commands and scores exist solely in memory at any
    # moment. Persisting them here is the difference between a clean restart
    # and one that quietly loses the last few seconds of every active attacker.
    with contextlib.suppress(Exception):
        await asyncio.wait_for(eng.flush_profiles(), timeout=15)
    await pool.close()
    await r.aclose()
    print("[analytics] stopped", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
