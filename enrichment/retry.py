"""
Retry policy shared by the worker loops.

Two decisions live here:

  delay()        — exponential backoff with jitter, capped at BACKOFF_MAX_S, for
                   the outer connection/stream loops.
  is_transient() — whether a failure is worth retrying at all.

    transient: timeouts, refused or reset connections, 5xx, rate limits. The
               item is fine; the world briefly is not. Retry with backoff.
    permanent: malformed records, schema violations, encoding errors. Retrying
               reproduces the failure forever, so log it and move on.

Anything unrecognised is treated as permanent for a single item (log and skip,
never fatal) — the outer loops retry regardless of class, because exiting is
always the worse option there.

KEEP IN SYNC across pipeline/, enrichment/ and analytics/ — separate images, so
this cannot be shared as a module.
"""
import asyncio
import os
import random

# Both tunable via .env; the defaults recover from a Redis/Postgres restart in
# seconds while capping a dead-dependency retry storm at one attempt a minute.
BACKOFF_BASE_S = float(os.environ.get("BACKOFF_BASE_S") or 1.0)
BACKOFF_MAX_S = float(os.environ.get("BACKOFF_MAX_S") or 60.0)

# Imported opportunistically: the three images do not ship the same clients
# (pipeline has no httpx, for instance), and a missing one simply means no
# exception of that family can be raised here.
try:
    import asyncpg
except ImportError:                     # pragma: no cover
    asyncpg = None
try:
    import httpx
except ImportError:                     # pragma: no cover
    httpx = None
try:
    import redis
except ImportError:                     # pragma: no cover
    redis = None


def delay(attempt: int) -> float:
    """Seconds to wait before attempt N (1-based), capped and jittered.

    The jitter is not decoration: three services reconnect to the same Redis
    and Postgres, and without it they retry in lockstep for as long as the
    outage lasts, hammering the dependency at exactly the moment it is trying
    to come back up.
    """
    ceiling = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** max(0, attempt - 1)))
    return random.uniform(ceiling / 2, ceiling)


async def sleep(attempt: int) -> float:
    """Back off before attempt N and report how long it waited (for logging)."""
    waited = delay(attempt)
    await asyncio.sleep(waited)
    return waited


def is_transient(ex: BaseException) -> bool:
    """True when retrying the same work could plausibly succeed."""
    if isinstance(ex, (asyncio.TimeoutError, TimeoutError, ConnectionError,
                       BrokenPipeError)):
        return True

    if redis is not None and isinstance(
            ex, (redis.ConnectionError, redis.TimeoutError,
                 redis.BusyLoadingError)):
        return True

    if httpx is not None:
        # TransportError covers connect/read/write/pool timeouts, resets and
        # protocol errors; a response that never arrived is always retryable.
        if isinstance(ex, (httpx.TimeoutException, httpx.TransportError)):
            return True
        if isinstance(ex, httpx.HTTPStatusError):
            code = ex.response.status_code
            return code == 429 or code >= 500

    if asyncpg is not None:
        if isinstance(ex, (asyncpg.PostgresConnectionError,
                           asyncpg.ConnectionDoesNotExistError,
                           asyncpg.ConnectionFailureError,
                           asyncpg.CannotConnectNowError,
                           asyncpg.TooManyConnectionsError,
                           asyncpg.AdminShutdownError,
                           asyncpg.CrashShutdownError,
                           asyncpg.QueryCanceledError,
                           asyncpg.DeadlockDetectedError,
                           asyncpg.SerializationError,
                           asyncpg.InterfaceError)):
            return True
        if isinstance(ex, asyncpg.PostgresError):
            # Everything else the server rejects — data errors, constraint and
            # schema violations — fails identically on every retry.
            return False

    # Refused / unreachable / reset sockets arrive as plain OSError once the
    # client-specific classes above have had their turn.
    if isinstance(ex, OSError):
        return True

    # A loop that re-raised with added context (`raise Wrapper(...) from ex`)
    # still has to be classified by whatever actually failed underneath.
    cause = ex.__cause__
    if cause is not None and cause is not ex:
        return is_transient(cause)
    return False


def oneline(ex: BaseException) -> str:
    """Exception text safe to drop into a single log line. Sensor and provider
    payloads reach these messages, so newlines are attacker-controlled."""
    return str(ex).replace("\n", " ").replace("\r", "")
