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


async def init_pool():
    global _pool
    dsn = (f'postgresql://{os.environ["PG_USER"]}:{os.environ["PG_PASSWORD"]}'
           f'@{os.environ["PG_HOST"]}:{os.environ["PG_PORT"]}/{os.environ["PG_DB"]}')
    _pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, init=_codecs)
    return _pool


def pool() -> asyncpg.Pool:
    assert _pool is not None, "pool not initialised"
    return _pool
