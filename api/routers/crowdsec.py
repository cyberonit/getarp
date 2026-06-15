"""Read-only views onto the CrowdSec LAPI: active decisions (bans enforced by the
firewall bouncer) and an aggregated overview for the management console."""
import os
from collections import Counter

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from auth import require_admin

router = APIRouter(prefix="/api/admin/crowdsec", tags=["crowdsec"])

LAPI_URL = os.environ.get("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
LAPI_KEY = os.environ["CROWDSEC_BOUNCER_KEY"]


async def _decisions():
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(f"{LAPI_URL}/v1/decisions", headers={"X-Api-Key": LAPI_KEY})
    if r.status_code != 200:
        raise HTTPException(502, "crowdsec LAPI unavailable")
    return r.json() or []


async def local_decisions():
    """Bans from this sensor's own detections (excludes the CAPI community blocklist)."""
    return [d for d in await _decisions() if d.get("origin") != "CAPI"]


@router.get("/decisions")
async def decisions(limit: int = Query(100, le=500), user=Depends(require_admin)):
    rows = await local_decisions()
    return [{
        "id": d.get("id"),
        "ip": d.get("value"),
        "scope": d.get("scope"),
        "type": d.get("type"),
        "scenario": d.get("scenario"),
        "duration": d.get("duration"),
        "origin": d.get("origin"),
    } for d in rows[:limit]]


@router.get("/overview")
async def overview(user=Depends(require_admin)):
    """Aggregated stats for the CrowdSec management console."""
    rows = await _decisions()
    local = [d for d in rows if d.get("origin") != "CAPI"]
    by_scenario = Counter(d.get("scenario") for d in local)
    by_type = Counter(d.get("type") for d in rows)
    return {
        "total_decisions": len(rows),
        "local_decisions": len(local),
        "capi_blocklist": len(rows) - len(local),
        "by_scenario": [{"scenario": k, "count": v} for k, v in by_scenario.most_common()],
        "by_type": [{"type": k, "count": v} for k, v in by_type.most_common()],
    }
