#!/usr/bin/env python3
"""getarp.net backend API. FastAPI + asyncpg + Redis pub/sub bridge for live status."""
import asyncio
import json
import os
import secrets
import time
from datetime import datetime, timezone

import redis.asyncio as redis
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

import audit
import db
import auth
from routers import data, admin, crowdsec, honeypot, docker_ops

COOKIE_NAME = "getarp_session"
CSRF_HEADER = "x-csrf-token"
SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "1") == "1"

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
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "x-csrf-token"])
app.include_router(data.router)
app.include_router(admin.router)
app.include_router(crowdsec.router)
app.include_router(honeypot.router)
app.include_router(docker_ops.router)

R = None
STATUS_CHANNEL = "status:live"
WS_TICKET_TTL = 30  # seconds — single-use ticket for WebSocket auth


@app.on_event("startup")
async def startup():
    global R
    await db.init_pool()
    await auth.seed_admin()
    R = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# ───────────────────────── auth ─────────────────────────
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900  # 15 min


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    ip = (request.headers.get("x-forwarded-for") or
          (request.client.host if request.client else "unknown")).split(",")[0].strip()
    key = f"login:fails:{ip}"
    fails = int(await R.get(key) or 0)
    if fails >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed login attempts, try again later")
    user = await auth.authenticate(body.username, body.password)
    if not user:
        async with R.pipeline() as p:
            await p.incr(key)
            await p.expire(key, LOGIN_WINDOW_SECONDS, nx=True)
            await p.execute()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad credentials")
    await R.delete(key)
    await audit.log(user["username"], "login", {"ip": ip})
    token, csrf = auth.make_token(user["username"], user["role"])
    resp = JSONResponse({"token_type": "bearer", "role": user["role"], "csrf_token": csrf})
    resp.set_cookie(
        COOKIE_NAME, token,
        httponly=True, secure=SECURE_COOKIE, samesite="strict",
        max_age=auth.EXPIRE * 60, path="/api")
    return resp


@app.post("/api/auth/logout")
async def logout(user=Depends(auth.current_user)):
    """Revoke the current token so it cannot be reused."""
    jti = user.get("jti")
    exp = user.get("exp", 0)
    if jti:
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
        await auth.revoke_token(jti, expires_at)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/api")
    return resp


@app.get("/api/me")
async def me(user=Depends(auth.current_user)):
    return {"username": user["username"], "role": user["role"]}


# ───────────────────────── WebSocket ticket (single-use, short-lived) ─────
@app.post("/api/auth/ws-ticket")
async def ws_ticket(user=Depends(auth.current_user)):
    """Issue a single-use, short-lived ticket for WebSocket authentication.
    The ticket is stored in Redis and consumed on WS connect — never appears
    in server logs or Referer headers like a query-param JWT would."""
    ticket = secrets.token_urlsafe(32)
    payload = json.dumps({"sub": user["username"], "role": user["role"]})
    await R.set(f"ws:ticket:{ticket}", payload, ex=WS_TICKET_TTL)
    return {"ticket": ticket}


# ───────────────────────── live status (the "every 5 min" view) ─────────────────────────
@app.get("/api/status")
@limiter.limit("60/minute")
async def status_now(request: Request):
    """Latest snapshot (5-min cadence) + a fast live counter for the header."""
    async with db.pool().acquire() as con:
        snap = await con.fetchrow(
            "SELECT * FROM status_snapshots ORDER BY ts DESC LIMIT 1")
        live_attackers = await con.fetchval(
            "SELECT count(DISTINCT src_ip) FROM events WHERE ts>now()-interval '5 min'")
        tracked_hosts = await con.fetchval("SELECT count(*) FROM ips")
        recent_attacks = await con.fetch(
            "SELECT ts, host(src_ip) AS src_ip, attack_type, service FROM attack_events "
            "ORDER BY ts DESC LIMIT 10")
    out = dict(snap) if snap else {}
    out["live_attackers"] = live_attackers or 0
    out["tracked_hosts"] = tracked_hosts or 0
    out["recent_attacks"] = [dict(r) for r in recent_attacks]
    return out


@app.get("/api/status/history")
@limiter.limit("60/minute")
async def status_history(request: Request, hours: int = Query(24, ge=1, le=720)):
    async with db.pool().acquire() as con:
        rows = await con.fetch(
            "SELECT ts, active_attackers, events_per_min, threat_level "
            "FROM status_snapshots WHERE ts > now() - ($1 * interval '1 hour') "
            "ORDER BY ts", hours)
    return [dict(r) for r in rows]


@app.get("/api/map")
@limiter.limit("60/minute")
async def attack_map(request: Request):
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
async def ws_status(ws: WebSocket, ticket: str = Query("")):
    if not ticket:
        await ws.close(code=4401, reason="missing ticket")
        return
    key = f"ws:ticket:{ticket}"
    payload = await R.get(key)
    if not payload:
        await ws.close(code=4401, reason="invalid or expired ticket")
        return
    await R.delete(key)

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
@limiter.limit("60/minute")
async def health(request: Request):
    return {"status": "ok"}
