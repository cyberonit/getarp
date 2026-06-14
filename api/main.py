#!/usr/bin/env python3
"""getarp.net backend API. FastAPI + asyncpg + Redis pub/sub bridge for live status."""
import asyncio
import json
import os

import redis.asyncio as redis
from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

import db
import auth
from routers import data, admin

app = FastAPI(title="getarp Defence Intelligence API", version="0.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://getarp.net", "https://www.getarp.net"],
    allow_methods=["*"], allow_headers=["*"])
app.include_router(data.router)
app.include_router(admin.router)

R = None
STATUS_CHANNEL = "status:live"


@app.on_event("startup")
async def startup():
    global R
    await db.init_pool()
    await auth.seed_admin()
    R = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# ───────────────────────── auth ─────────────────────────
@app.post("/api/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = await auth.authenticate(form.username, form.password)
    if not user:
        from fastapi import HTTPException, status
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    return {"access_token": auth.make_token(user["username"], user["role"]),
            "token_type": "bearer", "role": user["role"]}


@app.get("/api/me")
async def me(user=Depends(auth.current_user)):
    return user


# ───────────────────────── live status (the "every 5 min" view) ─────────────────────────
@app.get("/api/status")
async def status_now():
    """Latest snapshot (5-min cadence) + a fast live counter for the header."""
    async with db.pool().acquire() as con:
        snap = await con.fetchrow(
            "SELECT * FROM status_snapshots ORDER BY ts DESC LIMIT 1")
        live_attackers = await con.fetchval(
            "SELECT count(DISTINCT src_ip) FROM events WHERE ts>now()-interval '5 min'")
        recent_attacks = await con.fetch(
            "SELECT ts, src_ip::text, attack_type, service FROM attack_events "
            "ORDER BY ts DESC LIMIT 10")
    out = dict(snap) if snap else {}
    out["live_attackers"] = live_attackers or 0
    out["recent_attacks"] = [dict(r) for r in recent_attacks]
    return out


@app.get("/api/status/history")
async def status_history(hours: int = 24):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT ts, active_attackers, events_per_min, threat_level "
            "FROM status_snapshots WHERE ts > now()-($1||' hours')::interval "
            "ORDER BY ts", str(hours))
    return [dict(r) for r in rows]


@app.get("/api/map")
async def attack_map():
    """Points for the world map: one per enriched attacking IP with a country."""
    async with db.pool().acquire() as con:
        rows = await con.fetch("""
            SELECT i.src_ip::text, i.threat_score, i.classification,
                   e.country, e.org
            FROM ips i JOIN ip_enrichment e ON e.src_ip=i.src_ip
            WHERE e.country IS NOT NULL AND i.last_seen > now()-interval '24 hours'
            ORDER BY i.threat_score DESC LIMIT 500""")
    return [dict(r) for r in rows]


# ───────────────────────── WebSocket: push live events ─────────────────────────
@app.websocket("/api/ws/status")
async def ws_status(ws: WebSocket):
    await ws.accept()
    pubsub = R.pubsub()
    await pubsub.subscribe(STATUS_CHANNEL)
    try:
        async for msg in pubsub.listen():
            if msg.get("type") == "message":
                await ws.send_text(msg["data"])
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(STATUS_CHANNEL)
        await pubsub.close()


@app.get("/api/health")
async def health():
    return {"status": "ok"}
