"""
Spy harness for the pipeline ingestor.

External dependencies are replaced, never contacted:
  * Postgres — SpyPool records every execute/fetchrow; the ips upsert always
    reports "new IP" so the enrich-queue path is exercised too.
  * Redis — SpyRedis records xadd calls per stream.

SENSOR_PUBLIC_IP must be in the environment BEFORE ingestor is imported:
SELF_IPS is resolved at module import.
"""
import asyncio
import contextlib
import os
import sys
from collections import defaultdict

import pytest

os.environ["SENSOR_PUBLIC_IP"] = "192.0.2.1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ingestor  # noqa: E402


class SpyRedis:
    def __init__(self):
        self.streams = defaultdict(list)

    async def xadd(self, stream, fields, **kw):
        self.streams[stream].append(fields)


def _reject_nuls(args):
    """Mimic Postgres, which stores NUL (U+0000) in neither text nor jsonb.
    Without this the spy silently accepts payloads the real database rejects,
    so a NUL-handling regression would pass the suite and only surface in
    production as a dropped event."""
    for a in args:
        if isinstance(a, str) and ("\x00" in a or "\\u0000" in a):
            raise ValueError(
                'invalid byte sequence for encoding "UTF8": 0x00')


class _SpyCon:
    def __init__(self, log, conflicts=()):
        self.log = log
        self.conflicts = conflicts

    async def execute(self, sql, *args):
        _reject_nuls(args)
        self.log.append(("execute", sql, args))

    async def fetchrow(self, sql, *args):
        _reject_nuls(args)
        self.log.append(("fetchrow", sql, args))
        # Postgres returns no row when ON CONFLICT DO NOTHING suppresses an
        # insert. Without modelling that, a replayed record would look freshly
        # stored and the double-count guard would never be exercised.
        if any(marker in sql for marker in self.conflicts):
            return None
        return {"inserted": True}


class SpyPool:
    def __init__(self, conflicts=()):
        self.log = []
        self.conflicts = conflicts

    def acquire(self):
        return _SpyAcquire(_SpyCon(self.log, self.conflicts))


class _SpyAcquire:
    def __init__(self, con):
        self.con = con

    async def __aenter__(self):
        return self.con

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def spy_pool():
    return SpyPool()


@pytest.fixture
def spy_redis():
    return SpyRedis()


async def _run_consumer(pool, r, records):
    """Run the real consumer loop over a list of (sensor, record) tuples."""
    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.get_event_loop().create_task(ingestor.consumer(queue, pool, r))
    for item in records:
        await queue.put(item)
    while not queue.empty():
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)   # let the last dequeued record finish
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    return pool, r


@pytest.fixture
def drive_consumer(spy_pool, spy_redis):
    async def _drive(records):
        return await _run_consumer(spy_pool, spy_redis, records)
    return _drive


@pytest.fixture
def drive_consumer_replayed(spy_redis):
    """As drive_consumer, but the events insert reports a conflict — i.e. the
    record was already stored and is being re-read after a restart."""
    async def _drive(records):
        pool = SpyPool(conflicts=("INSERT INTO events",))
        return await _run_consumer(pool, spy_redis, records)
    return _drive
