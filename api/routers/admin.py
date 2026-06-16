"""Auth-gated admin endpoints: runtime settings the operator can change."""
import html as _html
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import db
from auth import require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Keys consumed by pipeline/analytics/enrichment at startup (see their
# settings.get(...) calls / db/init.sql defaults). Reject anything else so the
# settings table can't be used as an arbitrary key/value store.
ALLOWED_SETTINGS = {
    "enrichment_provider",
    "scan_port_threshold",
    "scan_window_seconds",
    "bruteforce_threshold",
    "bruteforce_window_seconds",
    "status_interval_seconds",
    "report_cron_hour",
    "enabled_detectors",
}


class Setting(BaseModel):
    key: str
    value: object


@router.get("/settings")
async def get_settings(user=Depends(require_admin)):
    async with db.pool().acquire() as con:
        rows = await con.fetch("SELECT key, value, updated_at FROM settings ORDER BY key")
    return [dict(r) for r in rows]


@router.put("/settings")
async def put_setting(s: Setting, user=Depends(require_admin)):
    if s.key not in ALLOWED_SETTINGS:
        raise HTTPException(400, f"unknown setting key: {s.key!r}")
    async with db.pool().acquire() as con:
        await con.execute(
            """INSERT INTO settings (key, value, updated_at) VALUES ($1,$2, now())
               ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()""",
            s.key, s.value)  # pool codec handles JSONB encoding
    # NOTE: services read settings at startup; some changes need a service restart.
    return {"ok": True, "note": "some settings apply on next service restart"}


def _render_report_html(kind: str, s: dict) -> str:
    esc = _html.escape
    rows = "".join(
        f"<tr><td>{esc(str(a['src_ip']))}</td><td>{esc(str(a.get('threat_score')))}</td>"
        f"<td>{esc(str(a.get('classification')))}</td>"
        f"<td>{esc(str(a.get('country') or '?'))}</td>"
        f"<td>{esc(str(a.get('asn') or '?'))}</td>"
        f"<td>{esc(str(a.get('org') or '?'))}</td></tr>"
        for a in s.get("top_attackers", []))
    atk = "".join(f"<li>{esc(str(a['attack_type']))}: {esc(str(a['n']))}</li>"
                  for a in s.get("attacks_by_type", []))
    return f"""<html><body style="font-family:system-ui">
<h1>getarp.net {esc(kind)} report</h1>
<p>Events: {esc(str(s.get('events', 0)))} &middot; Unique IPs: {esc(str(s.get('unique_ips', 0)))} &middot; Scans: {esc(str(s.get('scans', 0)))}</p>
<h3>Attacks by type</h3><ul>{atk}</ul>
<h3>Top attackers</h3>
<table border=1 cellpadding=4><tr><th>IP</th><th>Score</th><th>Class</th><th>Country</th><th>AS</th><th>Org</th></tr>
{rows}</table></body></html>"""


@router.post("/reports/regenerate-html")
async def regenerate_report_html(user=Depends(require_admin)):
    async with db.pool().acquire() as con:
        rows = await con.fetch("SELECT id, kind, summary FROM reports ORDER BY id")
        updated = 0
        for row in rows:
            s = row["summary"] or {}
            new_html = _render_report_html(row["kind"], s)
            await con.execute("UPDATE reports SET html=$1 WHERE id=$2", new_html, row["id"])
            updated += 1
    return {"updated": updated}


@router.get("/health")
async def health(user=Depends(require_admin)):
    async with db.pool().acquire() as con:
        ev = await con.fetchval("SELECT count(*) FROM events WHERE ts>now()-interval '1 hour'")
        ips = await con.fetchval("SELECT count(*) FROM ips")
    return {"events_last_hour": ev, "total_ips": ips}
