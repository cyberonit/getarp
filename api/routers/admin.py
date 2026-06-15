"""Auth-gated admin endpoints: runtime settings the operator can change."""
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


@router.get("/health")
async def health(user=Depends(require_admin)):
    async with db.pool().acquire() as con:
        ev = await con.fetchval("SELECT count(*) FROM events WHERE ts>now()-interval '1 hour'")
        ips = await con.fetchval("SELECT count(*) FROM ips")
    return {"events_last_hour": ev, "total_ips": ips}
