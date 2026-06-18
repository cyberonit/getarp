import json
import os
import asyncpg

_pool: asyncpg.Pool | None = None


async def _codecs(con):
    # Without this, asyncpg returns JSONB as raw strings; the frontend then
    # calls .map() on a string and the dashboard crashes. Decode at the edge.
    for t in ("json", "jsonb"):
        await con.set_type_codec(t, encoder=json.dumps, decoder=json.loads,
                                 schema="pg_catalog")


def _db_user():
    svc_pw = os.environ.get("SVC_DB_PASSWORD", "")
    if svc_pw:
        return os.environ.get("SVC_DB_USER", os.environ["PG_USER"]), svc_pw
    return os.environ["PG_USER"], os.environ["PG_PASSWORD"]


async def init_pool():
    global _pool
    user, password = _db_user()
    _pool = await asyncpg.create_pool(
        host=os.environ["PG_HOST"],
        port=int(os.environ["PG_PORT"]),
        database=os.environ["PG_DB"],
        user=user,
        password=password,
        min_size=2, max_size=10, init=_codecs,
    )
    return _pool


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("pool not initialised")
    return _pool
