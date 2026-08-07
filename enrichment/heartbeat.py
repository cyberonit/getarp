"""
Liveness heartbeats for the long-running worker loops.

Every concurrent loop in a worker touches its own file under HEARTBEAT_DIR on
each successful iteration. Two things read those files:

  * healthcheck.py, run by the container HEALTHCHECK — makes a wedged loop
    visible as "(unhealthy)" in `docker ps` instead of a container that looks
    fine while doing nothing.
  * watchdog(), an in-process task — exits the process when a beat goes stale.

The watchdog is what actually recovers a hang. Compose does NOT restart on
health status: `restart: unless-stopped` fires on process *exit* only, and an
unhealthy container sits there unhealthy forever. A supervisor container and
the Docker socket are both ruled out by this project's security model, so the
worker itself has to notice and die, and let the restart policy replace it.

Per-loop beats, not one per process: each worker runs several concurrent tasks,
and a single shared beat stays fresh while one of them is wedged — which is
precisely the failure this is here to catch.

Heartbeats are files rather than Redis keys on purpose. A Redis-backed beat
cannot distinguish "this worker is stuck" from "Redis is briefly unreachable",
so a Redis blip would restart all three workers at once — the opposite of what
is wanted. A file measures only the worker's own progress.

KEEP IN SYNC across pipeline/, enrichment/ and analytics/ — separate images, so
this cannot be shared as a module (same constraint as the NUL sanitizers in
pipeline/ingestor.py and enrichment/base.py).
"""
import asyncio
import os
import sys
import time

HEARTBEAT_DIR = os.environ.get("HEARTBEAT_DIR", "/tmp/health")

# The busiest loops iterate once per ingested event, and a beat is a file
# write. Rate limit them: one-second resolution is far finer than any threshold
# these are compared against.
MIN_BEAT_INTERVAL_S = 1.0

_last: dict[str, float] = {}
_warned = False


def env_seconds(name: str, default: float) -> float:
    """Read a threshold from the environment, tolerating a blank or malformed
    value — a bad tuning knob must not stop the worker from starting."""
    raw = os.environ.get(name)
    if not raw:
        return float(default)
    try:
        return max(1.0, float(raw))
    except ValueError:
        print(f"[heartbeat] {name}={raw!r} is not a number, using {default}",
              flush=True)
        return float(default)


def beat(name: str) -> None:
    """Record that `name` completed an iteration. Never raises: a liveness
    mechanism must not be able to kill the thing it is measuring."""
    global _warned
    now = time.time()
    if now - _last.get(name, 0.0) < MIN_BEAT_INTERVAL_S:
        return
    _last[name] = now
    try:
        os.makedirs(HEARTBEAT_DIR, exist_ok=True)
        with open(os.path.join(HEARTBEAT_DIR, name), "w") as fh:
            fh.write(f"{now:.3f}\n")
    except OSError as ex:
        if not _warned:
            _warned = True
            print(f"[heartbeat] cannot write {HEARTBEAT_DIR}: {ex} — watchdog "
                  f"and healthcheck are blind", flush=True)


def start(specs: dict) -> None:
    """Seed every beat at process start, so a loop that has not reached its
    first iteration yet reads as young rather than missing."""
    for name in specs:
        _last.pop(name, None)
        beat(name)


def age(name: str):
    """Seconds since `name` last beat, or None when it never has."""
    try:
        return time.time() - os.stat(os.path.join(HEARTBEAT_DIR, name)).st_mtime
    except OSError:
        return None


def stale(specs: dict):
    """(name, age, max_age) for the first loop past its threshold, else None."""
    for name, max_age in specs.items():
        seen = age(name)
        if seen is None or seen > max_age:
            return name, seen, max_age
    return None


def check(specs: dict) -> int:
    """Entry point for healthcheck.py: prints the reason, returns an exit code."""
    bad = stale(specs)
    if bad is None:
        return 0
    name, seen, max_age = bad
    when = "never" if seen is None else f"{seen:.0f}s ago"
    print(f"unhealthy: loop '{name}' last beat {when} "
          f"(threshold {max_age:.0f}s)", file=sys.stderr)
    return 1


async def watchdog(specs: dict, poll_s: float = 15.0) -> None:
    """Exit the process once a loop stops beating, so the restart policy can
    replace it. This, not the HEALTHCHECK, is what recovers a hang."""
    while True:
        await asyncio.sleep(poll_s)
        bad = stale(specs)
        if bad is None:
            continue
        name, seen, max_age = bad
        when = "never" if seen is None else f"{seen:.0f}s ago"
        print(f"[watchdog] loop '{name}' last beat {when}, threshold "
              f"{max_age:.0f}s — exiting for restart", flush=True)
        sys.stdout.flush()
        sys.stderr.flush()
        # _exit, not sys.exit: something in this process is already wedged by
        # definition, so unwinding through it — atexit hooks, task cancellation,
        # connection teardown — is exactly what cannot be relied on here.
        os._exit(1)
