"""JWT auth for the admin backend. Public dashboard endpoints are unauthenticated
(read-only); settings/admin endpoints require a valid token."""
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
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


def make_token(sub: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=EXPIRE)
    return jwt.encode({"sub": sub, "role": role, "exp": exp}, SECRET, algorithm=ALGO)


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


async def current_user(token: str = Depends(oauth2)) -> dict:
    cred_err = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
    except InvalidTokenError:
        raise cred_err
    username = payload.get("sub")
    if not username:
        raise cred_err
    async with db.pool().acquire() as con:
        row = await con.fetchrow(
            "SELECT username, role FROM users WHERE username=$1", username)
    if not row:
        raise cred_err
    return {"username": row["username"], "role": row["role"]}


async def require_admin(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return user
