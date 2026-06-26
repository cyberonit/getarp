"""Data endpoints powering the dashboard. Aggregate/summary endpoints are public;
endpoints that expose raw event data (commands, usernames, passwords) require auth."""
import csv
import io
import ipaddress
import os

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import auth
import db

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api", tags=["data"])

DOCS_DIR = os.environ.get("DOCS_DIR", "/app/docs")
ALLOWED_DOCS = {
    "hld.pdf": "High-Level Design",
}


@router.get("/docs")
@limiter.limit("60/minute")
async def list_docs(request: Request):
    out = []
    for name, label in ALLOWED_DOCS.items():
        path = os.path.join(DOCS_DIR, name)
        if os.path.isfile(path):
            out.append({"name": name, "label": label, "size": os.path.getsize(path)})
    return out


@router.get("/docs/{name}")
@limiter.limit("60/minute")
async def get_doc(request: Request, name: str):
    if name not in ALLOWED_DOCS:
        raise HTTPException(404, "not found")
    path = os.path.join(DOCS_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    return FileResponse(path, media_type="application/pdf", filename=name)


@router.get("/ips")
@limiter.limit("60/minute")
async def list_ips(request: Request, limit: int = Query(100, ge=1, le=500), order: str = "threat_score"):
    order_col = {"threat_score": "threat_score", "last_seen": "last_seen",
                 "event_count": "event_count"}.get(order, "threat_score")
    async with db.pool().acquire() as con:
        rows = await con.fetch(f"""
            SELECT host(i.src_ip) AS src_ip, i.first_seen, i.last_seen, i.event_count,
                   i.services_hit, i.ports_hit, i.threat_score, i.classification,
                   e.country, e.asn, e.org, e.reputation, e.is_known_attacker
            FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip
            ORDER BY i.{order_col} DESC NULLS LAST LIMIT $1""", limit)
    return [dict(r) for r in rows]


def _redact_attack_evidence(evidence):
    """Strip plaintext passwords from attack evidence before serving."""
    if not isinstance(evidence, dict):
        return evidence
    redacted = dict(evidence)
    if "sample_creds" in redacted:
        redacted["sample_creds"] = [
            [pair[0], "***"] if isinstance(pair, (list, tuple)) and len(pair) >= 2
            else pair
            for pair in redacted["sample_creds"]
        ]
    return redacted


@router.get("/ips/{ip}")
@limiter.limit("60/minute")
async def ip_detail(request: Request, ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "invalid IP address")
    async with db.pool().acquire() as con:
        info = await con.fetchrow("""
            SELECT host(i.src_ip) AS src_ip, i.first_seen, i.last_seen, i.event_count,
                   i.services_hit, i.ports_hit, i.threat_score, i.classification,
                   e.country, e.asn, e.org, e.reputation, e.categories,
                   e.is_known_attacker, e.confidence
            FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip
            WHERE i.src_ip=$1""", ip)
        events = await con.fetch("""
            SELECT ts, sensor, service, event_type, dst_port, username, command, signature
            FROM events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 100""", ip)
        prof = await con.fetchrow("""
            SELECT host(src_ip) AS src_ip, sessions, avg_session_s, commands_seen,
                   tooling_hints, tactics, cluster_id, threat_score, updated_at, detail
            FROM behavior_profiles WHERE src_ip=$1""", ip)
        scans = await con.fetch("""
            SELECT id, ts, host(src_ip) AS src_ip, scan_type, port_count, ports, window_s, detail
            FROM scan_events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 20""", ip)
        attacks = await con.fetch("""
            SELECT id, ts, host(src_ip) AS src_ip, attack_type, service, evidence, severity, ai_score
            FROM attack_events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 50""", ip)
    event_rows = []
    for r in events:
        row = dict(r)
        row.pop("password", None)
        event_rows.append(row)
    attack_rows = []
    for r in attacks:
        row = dict(r)
        row["evidence"] = _redact_attack_evidence(row.get("evidence"))
        attack_rows.append(row)
    return {
        "info": dict(info) if info else None,
        "events": event_rows,
        "profile": dict(prof) if prof else None,
        "scans": [dict(r) for r in scans],
        "attacks": attack_rows,
    }


@router.get("/events/latest")
@limiter.limit("60/minute")
async def latest_events(request: Request, limit: int = Query(50, ge=1, le=200),
                        user=Depends(auth.current_user)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT ts, sensor, service, event_type, host(src_ip) AS src_ip, "
            "dst_port, username, command, signature "
            "FROM events ORDER BY ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/scans")
@limiter.limit("60/minute")
async def scans(request: Request, limit: int = Query(100, ge=1, le=500),
                window: str = Query("24h"), group_by: str = Query("")):
    intervals = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days", "1y": "1 year"}
    iv = intervals.get(window)
    if not iv:
        raise HTTPException(400, "invalid window")
    time_filter = f"WHERE s.ts > now() - interval '{iv}'"

    if group_by == "scan_type":
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                f"SELECT s.scan_type AS label, count(*) AS n, avg(s.port_count)::int AS avg_ports "
                f"FROM scan_events s {time_filter} AND s.scan_type IS NOT NULL "
                f"GROUP BY s.scan_type ORDER BY n DESC LIMIT $1", limit)
        return [dict(r) for r in rows]

    if group_by == "as":
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                f"SELECT e.asn, e.org, count(*) AS n, avg(s.port_count)::int AS avg_ports "
                f"FROM scan_events s LEFT JOIN ip_enrichment e ON e.src_ip=s.src_ip "
                f"{time_filter} AND e.asn IS NOT NULL "
                f"GROUP BY e.asn, e.org ORDER BY n DESC LIMIT $1", limit)
        return [dict(r) for r in rows]

    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT s.id, s.ts, host(s.src_ip) AS src_ip, s.scan_type, s.port_count, s.ports, s.detail, "
            f"e.country, e.asn, e.org "
            f"FROM scan_events s LEFT JOIN ip_enrichment e ON e.src_ip=s.src_ip "
            f"{time_filter} ORDER BY s.ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/attacks")
@limiter.limit("60/minute")
async def attacks(request: Request, limit: int = Query(100, ge=1, le=500),
                  window: str = Query("24h"), group_by: str = Query("")):
    intervals = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days", "1y": "1 year"}
    iv = intervals.get(window)
    if not iv:
        raise HTTPException(400, "invalid window")
    time_filter = f"WHERE a.ts > now() - interval '{iv}'"

    if group_by == "service":
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                f"SELECT a.service AS label, count(*) AS n, avg(a.severity)::int AS avg_severity "
                f"FROM attack_events a {time_filter} AND a.service IS NOT NULL "
                f"GROUP BY a.service ORDER BY n DESC LIMIT $1", limit)
        return [dict(r) for r in rows]

    if group_by == "as":
        async with db.pool().acquire() as con:
            rows = await con.fetch(
                f"SELECT e.asn, e.org, count(*) AS n, avg(a.severity)::int AS avg_severity "
                f"FROM attack_events a LEFT JOIN ip_enrichment e ON e.src_ip=a.src_ip "
                f"{time_filter} AND e.asn IS NOT NULL "
                f"GROUP BY e.asn, e.org ORDER BY n DESC LIMIT $1", limit)
        return [dict(r) for r in rows]

    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT a.id, a.ts, host(a.src_ip) AS src_ip, a.attack_type, a.service, a.severity, a.evidence, "
            f"e.country, e.asn, e.org "
            f"FROM attack_events a LEFT JOIN ip_enrichment e ON e.src_ip=a.src_ip "
            f"{time_filter} ORDER BY a.ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/behavior")
@limiter.limit("60/minute")
async def behavior(request: Request, limit: int = Query(100, ge=1, le=500),
                   window: str = Query("24h")):
    intervals = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days", "1y": "1 year"}
    iv = intervals.get(window)
    if not iv:
        raise HTTPException(400, "invalid window")
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT host(b.src_ip) AS src_ip, b.sessions, b.threat_score, b.tooling_hints, b.tactics, "
            f"b.commands_seen, b.updated_at, e.country, e.asn, e.org "
            f"FROM behavior_profiles b LEFT JOIN ip_enrichment e ON e.src_ip=b.src_ip "
            f"WHERE b.updated_at > now() - interval '{iv}' "
            f"ORDER BY b.threat_score DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/top-countries")
@limiter.limit("60/minute")
async def top_countries(request: Request, window: str = Query("1h")):
    intervals = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}
    iv = intervals.get(window)
    if not iv:
        raise HTTPException(400, "invalid window")
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT e.country, count(*) n "
            f"FROM events ev JOIN ip_enrichment e ON e.src_ip = ev.src_ip "
            f"WHERE ev.ts > now() - interval '{iv}' AND e.country IS NOT NULL "
            f"AND e.country != '' "
            f"GROUP BY e.country ORDER BY n DESC LIMIT 10")
    return [dict(r) for r in rows]


@router.get("/top-as")
@limiter.limit("60/minute")
async def top_as(request: Request, window: str = Query("1h")):
    intervals = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}
    iv = intervals.get(window)
    if not iv:
        raise HTTPException(400, "invalid window")
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT e.asn, e.org, count(*) n "
            f"FROM events ev JOIN ip_enrichment e ON e.src_ip = ev.src_ip "
            f"WHERE ev.ts > now() - interval '{iv}' AND e.asn IS NOT NULL "
            f"AND e.asn != '' "
            f"GROUP BY e.asn, e.org ORDER BY n DESC LIMIT 10")
    return [dict(r) for r in rows]


@router.get("/reports")
@limiter.limit("60/minute")
async def reports(request: Request, limit: int = Query(30, ge=1, le=100)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT id, created_at, kind, period_from, period_to, summary "
            "FROM reports ORDER BY created_at DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/reports/{rid}")
@limiter.limit("60/minute")
async def report_html(request: Request, rid: int = Path(ge=1, le=2_147_483_647)):
    async with db.pool().acquire() as con:
        row = await con.fetchrow("SELECT html, summary FROM reports WHERE id=$1", rid)
    return {"html": row["html"] if row else "", "summary": row["summary"] if row else {}}


# Cell values starting with these characters are interpreted as formulas by
# Excel/Sheets/LibreOffice; prefix with a single quote to defuse CSV/formula
# injection from attacker-controlled honeypot fields (commands, usernames, ...).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_row(values):
    out = []
    for v in values:
        if isinstance(v, str) and v[:1] in _CSV_FORMULA_PREFIXES:
            v = "'" + v
        out.append(v)
    return out


@router.get("/reports/{rid}/csv")
@limiter.limit("60/minute")
async def report_csv(request: Request, rid: int = Path(ge=1, le=2_147_483_647)):
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT id, created_at, kind, period_from, period_to, summary FROM reports WHERE id=$1", rid)
    if not row:
        raise HTTPException(404, "not found")
    summary = row["summary"] or {}

    buf = io.StringIO()
    w = csv.writer(buf)

    # Executive summary
    w.writerow(["EXECUTIVE SUMMARY"])
    w.writerow(["report_id", row["id"]])
    w.writerow(["kind", row["kind"]])
    w.writerow(["created_at", row["created_at"]])
    w.writerow(["period_from", row["period_from"]])
    w.writerow(["period_to", row["period_to"]])
    w.writerow([])
    w.writerow(["total_events", summary.get("events", "")])
    w.writerow(["unique_ips", summary.get("unique_ips", "")])
    w.writerow(["scans", summary.get("scans", "")])
    w.writerow(["blocked_ips", summary.get("blocked_ips", "")])
    w.writerow([])
    w.writerow(["ATTACKS BY TYPE"])
    w.writerow(["attack_type", "count"])
    for a in summary.get("attacks_by_type", []):
        w.writerow([a.get("attack_type"), a.get("n")])
    w.writerow([])

    # Top attackers
    w.writerow(["TOP ATTACKERS"])
    w.writerow(["src_ip", "threat_score", "classification", "country", "asn", "org"])
    for a in summary.get("top_attackers", []):
        w.writerow(_csv_row([a.get("src_ip"), a.get("threat_score"), a.get("classification"),
                              a.get("country"), a.get("asn"), a.get("org")]))

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report-{rid}.csv"'},
    )
