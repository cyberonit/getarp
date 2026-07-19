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


class _SpyCon:
    def __init__(self, log):
        self.log = log

    async def execute(self, sql, *args):
        self.log.append(("execute", sql, args))

    async def fetchrow(self, sql, *args):
        self.log.append(("fetchrow", sql, args))
        return {"inserted": True}


class SpyPool:
    def __init__(self):
        self.log = []

    def acquire(self):
        return _SpyAcquire(_SpyCon(self.log))


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


@pytest.fixture
def drive_consumer(spy_pool, spy_redis):
    """Run the real consumer loop over a list of (sensor, record) tuples."""
    async def _drive(records):
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.get_event_loop().create_task(
            ingestor.consumer(queue, spy_pool, spy_redis))
        for item in records:
            await queue.put(item)
        while not queue.empty():
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)   # let the last dequeued record finish
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return spy_pool, spy_redis
    return _drive
