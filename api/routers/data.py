"""Read-only data endpoints powering the public dashboard."""
from fastapi import APIRouter, Query
import db

router = APIRouter(prefix="/api", tags=["data"])


@router.get("/ips")
async def list_ips(limit: int = Query(100, le=500), order: str = "threat_score"):
    order_col = {"threat_score": "threat_score", "last_seen": "last_seen",
                 "event_count": "event_count"}.get(order, "threat_score")
    async with db.pool().acquire() as con:
        rows = await con.fetch(f"""
            SELECT i.src_ip::text, i.first_seen, i.last_seen, i.event_count,
                   i.services_hit, i.ports_hit, i.threat_score, i.classification,
                   e.country, e.asn, e.org, e.reputation, e.is_known_attacker
            FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip
            ORDER BY i.{order_col} DESC NULLS LAST LIMIT $1""", limit)
    return [dict(r) for r in rows]


@router.get("/ips/{ip}")
async def ip_detail(ip: str):
    async with db.pool().acquire() as con:
        info = await con.fetchrow("""
            SELECT i.*, e.country, e.asn, e.org, e.reputation, e.categories,
                   e.is_known_attacker, e.confidence
            FROM ips i LEFT JOIN ip_enrichment e ON e.src_ip=i.src_ip
            WHERE i.src_ip=$1""", ip)
        events = await con.fetch("""
            SELECT ts, sensor, service, event_type, dst_port, username, command, signature
            FROM events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 100""", ip)
        prof = await con.fetchrow("SELECT * FROM behavior_profiles WHERE src_ip=$1", ip)
        scans = await con.fetch(
            "SELECT * FROM scan_events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 20", ip)
        attacks = await con.fetch(
            "SELECT * FROM attack_events WHERE src_ip=$1 ORDER BY ts DESC LIMIT 50", ip)
    return {
        "info": dict(info) if info else None,
        "events": [dict(r) for r in events],
        "profile": dict(prof) if prof else None,
        "scans": [dict(r) for r in scans],
        "attacks": [dict(r) for r in attacks],
    }


@router.get("/scans")
async def scans(limit: int = Query(100, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT id, ts, src_ip::text, scan_type, port_count, ports, detail "
            "FROM scan_events ORDER BY ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/attacks")
async def attacks(limit: int = Query(100, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT id, ts, src_ip::text, attack_type, service, severity, evidence "
            "FROM attack_events ORDER BY ts DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/behavior")
async def behavior(limit: int = Query(100, le=500)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT src_ip::text, sessions, threat_score, tooling_hints, tactics, "
            "commands_seen, updated_at FROM behavior_profiles "
            "ORDER BY threat_score DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/reports")
async def reports(limit: int = Query(30, le=100)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT id, created_at, kind, period_from, period_to, summary "
            "FROM reports ORDER BY created_at DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@router.get("/reports/{rid}")
async def report_html(rid: int):
    async with db.pool().acquire() as con:
        row = await con.fetchrow("SELECT html, summary FROM reports WHERE id=$1", rid)
    return {"html": row["html"] if row else "", "summary": row["summary"] if row else {}}
