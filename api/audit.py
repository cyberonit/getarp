"""Append-only audit log for privileged admin operations."""
import json
import db


async def log(username: str, action: str, detail: dict | None = None):
    async with db.pool().acquire() as con:
        await con.execute(
            "INSERT INTO audit_log (username, action, detail) VALUES ($1, $2, $3)",
            username, action, json.dumps(detail, default=str) if detail else None)
