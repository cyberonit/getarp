"""Read-only data endpoints powering the public dashboard."""
import csv
import io
import ipaddress
import os

from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import FileResponse, StreamingResponse
import db

router = APIRouter(prefix="/api", tags=["data"])

DOCS_DIR = os.environ.get("DOCS_DIR", "/app/docs")
ALLOWED_DOCS = {
    "hld.pdf": "High-Level Design",
}


@router.get("/docs")
async def list_docs():
    out = []
    for name, label in ALLOWED_DOCS.items():
        path = os.path.join(DOCS_DIR, name)
        if os.path.isfile(path):
            out.append({"name": name, "label": label, "size": os.path.getsize(path)})
    return out


@router.get("/docs/{name}")
async def get_doc(name: str):
    if name not in ALLOWED_DOCS:
        raise HTTPException(404, "not found")
    path = os.path.join(DOCS_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    return FileResponse(path, media_type="application/pdf", filename=name)


@router.get("/ips")
async def list_ips(limit: int = Query(100, ge=1, le=500), order: str = "threat_score"):
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


@router.get("/ips/{ip}")
async def ip_detail(ip: str):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "invalid IP address")
    async with db.pool().acquire() as con:
        info = await con.fetchrow("""
            SELECT host(i.src_ip) AS src_ip, i.first_seen, i.last_seen, i.event_count,
                   i.services_hit, i.ports_hit, i.threat_score, i.classification,
                   e.country, e.asn, e.org, e.reputation, e.categories,
                   e.is_known_attacker, e.confidence, e.raw as enrichment_raw
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
    return {
        "info": dict(info) if info else None,
        "events": [dict(r) for r in events],
        "profile": dict(prof) if prof else None,
        "scans": [dict(r) for r in scans],
        "attacks": [dict(r) for r in attacks],
    }


@router.get("/scans")
async def scans(limit: int = Query(100, ge=1, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT s.id, s.ts, host(s.src_ip) AS src_ip, s.scan_type, s.port_count, s.ports, s.detail, "
            "e.country, e.asn, e.org "
            "FROM scan_events s LEFT JOIN ip_enrichment e ON e.src_ip=s.src_ip "
            "ORDER BY s.ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/attacks")
async def attacks(limit: int = Query(100, ge=1, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT a.id, a.ts, host(a.src_ip) AS src_ip, a.attack_type, a.service, a.severity, a.evidence, "
            "e.country, e.asn, e.org "
            "FROM attack_events a LEFT JOIN ip_enrichment e ON e.src_ip=a.src_ip "
            "ORDER BY a.ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/behavior")
async def behavior(limit: int = Query(100, ge=1, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT host(b.src_ip) AS src_ip, b.sessions, b.threat_score, b.tooling_hints, b.tactics, "
            "b.commands_seen, b.updated_at, e.country, e.asn, e.org "
            "FROM behavior_profiles b LEFT JOIN ip_enrichment e ON e.src_ip=b.src_ip "
            "ORDER BY b.threat_score DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/top-as")
async def top_as(window: str = Query("1h")):
    spans = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}
    span = spans.get(window)
    if not span:
        raise HTTPException(400, "invalid window")
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            f"SELECT e.asn, e.org, count(*) n "
            f"FROM events ev JOIN ip_enrichment e ON e.src_ip = ev.src_ip "
            f"WHERE ev.ts > now() - interval '{span}' AND e.asn IS NOT NULL "
            f"AND e.asn != '' "
            f"GROUP BY e.asn, e.org ORDER BY n DESC LIMIT 10")
    return [dict(r) for r in rows]


@router.get("/reports")
async def reports(limit: int = Query(30, ge=1, le=100)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT id, created_at, kind, period_from, period_to, summary "
            "FROM reports ORDER BY created_at DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/reports/{rid}")
async def report_html(rid: int = Path(ge=1, le=2_147_483_647)):
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
async def report_csv(rid: int = Path(ge=1, le=2_147_483_647)):
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
