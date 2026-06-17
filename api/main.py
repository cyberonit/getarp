#!/usr/bin/env python3
"""getarp.net backend API. FastAPI + asyncpg + Redis pub/sub bridge for live status."""
import asyncio
import json
import os
import time

import redis.asyncio as redis
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

import db
import auth
from routers import data, admin, crowdsec, honeypot

limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(
    title="getarp Defence Intelligence API",
    version="0.1",
    docs_url=None,      # disable Swagger UI in production
    redoc_url=None,     # disable ReDoc in production
    openapi_url=None,   # disable schema endpoint in production
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://getarp.net", "https://www.getarp.net"],
    allow_methods=["*"], allow_headers=["*"])
app.include_router(data.router)
app.include_router(admin.router)
app.include_router(crowdsec.router)
app.include_router(honeypot.router)

R = None
STATUS_CHANNEL = "status:live"


@app.on_event("startup")
async def startup():
    global R
    await db.init_pool()
    await auth.seed_admin()
    R = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# ───────────────────────── auth ─────────────────────────
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900  # 15 min


@app.post("/api/auth/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    ip = (request.headers.get("x-forwarded-for") or
          (request.client.host if request.client else "unknown")).split(",")[0].strip()
    key = f"login:fails:{ip}"
    fails = int(await R.get(key) or 0)
    if fails >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed login attempts, try again later")
    user = await auth.authenticate(form.username, form.password)
    if not user:
        async with R.pipeline() as p:
            await p.incr(key)
            await p.expire(key, LOGIN_WINDOW_SECONDS, nx=True)
            await p.execute()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    await R.delete(key)
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
            "SELECT ts, host(src_ip) AS src_ip, attack_type, service FROM attack_events "
            "ORDER BY ts DESC LIMIT 10")
    out = dict(snap) if snap else {}
    out["live_attackers"] = live_attackers or 0
    out["recent_attacks"] = [dict(r) for r in recent_attacks]
    return out


@app.get("/api/status/history")
async def status_history(hours: int = Query(24, ge=1, le=720)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT ts, active_attackers, events_per_min, threat_level "
            "FROM status_snapshots WHERE ts > now() - ($1 * interval '1 hour') "
            "ORDER BY ts", hours)
    return [dict(r) for r in rows]


@app.get("/api/map")
async def attack_map():
    """Points for the world map: one per enriched attacking IP with a country."""
    async with db.pool().acquire() as con:
        rows = await con.fetch("""
            SELECT host(i.src_ip) AS src_ip, i.threat_score, i.classification,
                   e.country, e.org
            FROM ips i JOIN ip_enrichment e ON e.src_ip=i.src_ip
            WHERE e.country IS NOT NULL AND i.last_seen > now()-interval '24 hours'
            ORDER BY i.threat_score DESC LIMIT 500""")
    return [dict(r) for r in rows]


# ───────────────────────── WebSocket: push live events ─────────────────────────
@app.websocket("/api/ws/status")
async def ws_status(ws: WebSocket, token: str = Query(...)):
    # Browsers can't send Authorization headers on WS connections; use query param.
    try:
        payload = jwt.decode(token, auth.SECRET, algorithms=[auth.ALGO])
        if not payload.get("sub"):
            raise ValueError
    except (InvalidTokenError, ValueError):
        await ws.close(code=4401)
        return
    exp = payload.get("exp", 0)
    await ws.accept()
    pubsub = R.pubsub()
    await pubsub.subscribe(STATUS_CHANNEL)
    try:
        async for msg in pubsub.listen():
            if time.time() > exp:
                await ws.close(code=4401)
                break
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
