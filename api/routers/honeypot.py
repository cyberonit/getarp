"""Read-only viewer for the Cowrie honeypot's session log."""
import asyncio
import json
import os

from fastapi import APIRouter, Depends, Query

from auth import require_admin

router = APIRouter(prefix="/api/admin/cowrie", tags=["cowrie"])

LOG_DIR = os.environ.get("LOG_DIR", "/data/logs")
COWRIE_LOG = os.path.join(LOG_DIR, "cowrie.json")

# how much of the tail of the log file to scan for recent sessions
TAIL_BYTES = 2 * 1024 * 1024


def _tail_events():
    try:
        size = os.path.getsize(COWRIE_LOG)
    except OSError:
        return []
    with open(COWRIE_LOG, "rb") as f:
        if size > TAIL_BYTES:
            f.seek(size - TAIL_BYTES)
        data = f.read()
    events = []
    for line in data.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


@router.get("/sessions")
async def sessions(limit: int = Query(50, le=200), user=Depends(require_admin)):
    sessions = {}
    for e in await asyncio.to_thread(_tail_events):
        sid = e.get("session")
        if not sid:
            continue
        s = sessions.setdefault(sid, {
            "session": sid, "src_ip": e.get("src_ip"), "protocol": e.get("protocol"),
            "start": None, "end": None, "logins": [], "commands": [], "files": [],
        })
        ts = e.get("timestamp")
        if ts:
            if s["start"] is None or ts < s["start"]:
                s["start"] = ts
            if s["end"] is None or ts > s["end"]:
                s["end"] = ts

        eventid = e.get("eventid", "")
        if eventid in ("cowrie.login.failed", "cowrie.login.success"):
            s["logins"].append({
                "username": e.get("username"), "password": e.get("password"),
                "success": eventid == "cowrie.login.success",
            })
        elif eventid in ("cowrie.command.input", "cowrie.command.failed"):
            s["commands"].append(e.get("input"))
        elif eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            s["files"].append({
                "direction": "download" if "download" in eventid else "upload",
                "url": e.get("url"), "outfile": e.get("outfile"),
            })

    out = sorted(sessions.values(), key=lambda s: s["end"] or "", reverse=True)
    return out[:limit]
