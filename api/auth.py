"""JWT auth for the admin backend. Public dashboard endpoints are unauthenticated
(read-only); settings/admin endpoints require a valid token."""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

import db

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
SECRET = os.environ["JWT_SECRET"]
ALGO = "HS256"
EXPIRE = int(os.environ.get("JWT_EXPIRE_MINUTES", 60))


def hash_pw(p: str) -> str:
    return pwd.hash(p)


def verify_pw(p: str, h: str) -> bool:
    return pwd.verify(p, h)


def make_token(sub: str, role: str) -> tuple[str, str]:
    exp = datetime.now(timezone.utc) + timedelta(minutes=EXPIRE)
    jti = uuid.uuid4().hex
    csrf = secrets.token_urlsafe(32)
    token = jwt.encode({"sub": sub, "role": role, "exp": exp, "jti": jti, "csrf": csrf},
                       SECRET, algorithm=ALGO)
    return token, csrf


async def revoke_token(jti: str, expires_at: datetime):
    async with db.pool().acquire() as con:
        await con.execute(
            "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) "
            "ON CONFLICT DO NOTHING", jti, expires_at)


async def is_revoked(jti: str) -> bool:
    async with db.pool().acquire() as con:
        return bool(await con.fetchval(
            "SELECT 1 FROM revoked_tokens WHERE jti=$1", jti))


async def cleanup_expired_revocations():
    async with db.pool().acquire() as con:
        await con.execute(
            "DELETE FROM revoked_tokens WHERE expires_at < now()")


async def seed_admin():
    """Create the bootstrap admin from env on first run only."""
    async with db.pool().acquire() as con:
        exists = await con.fetchval("SELECT 1 FROM users LIMIT 1")
        if exists:
            return
        password = os.environ.get("ADMIN_PASSWORD")
        if not password or password == "admin":
            raise RuntimeError(
                "ADMIN_PASSWORD must be set to a non-default value. "
                "Refusing to start with insecure credentials."
            )
        await con.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'admin')",
            os.environ.get("ADMIN_USER", "admin"),
            hash_pw(password),
        )


async def authenticate(username: str, password: str):
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT username, password_hash, role FROM users WHERE username=$1", username)
    if not row or not verify_pw(password, row["password_hash"]):
        return None
    return row


async def _validate_token(raw_token: str) -> dict:
    """Decode + verify a JWT, checking revocation. Returns the user dict."""
    cred_err = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials",
                             headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(raw_token, SECRET, algorithms=[ALGO])
    except InvalidTokenError:
        raise cred_err
    username = payload.get("sub")
    jti = payload.get("jti")
    if not username:
        raise cred_err
    if jti and await is_revoked(jti):
        raise cred_err
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT username, role FROM users WHERE username=$1", username)
    if not row:
        raise cred_err
    return {"username": row["username"], "role": row["role"],
            "jti": jti, "exp": payload.get("exp", 0), "csrf": payload.get("csrf", "")}


COOKIE_NAME = "getarp_session"
CSRF_HEADER = "x-csrf-token"


def _extract_token(request) -> str:
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        return cookie
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated",
                        headers={"WWW-Authenticate": "Bearer"})


async def current_user(request: Request) -> dict:
    return await _validate_token(_extract_token(request))


async def require_admin(request: Request) -> dict:
    user = await current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    if request.method in ("POST", "PUT", "DELETE"):
        csrf_header = request.headers.get(CSRF_HEADER, "")
        if not csrf_header or csrf_header != user.get("csrf"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")
    return user
