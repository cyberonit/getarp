#!/usr/bin/env python3
"""Container HEALTHCHECK for the pipeline.

Run by Docker as `python /app/healthcheck.py`. Python is the one interpreter
guaranteed to exist in this image — there is no curl, no redis-cli — so the
check has no dependency the image does not already ship.

Two separate questions, both of which have to be answered here:

  * Is every loop still running? That is HEARTBEATS, and the watchdog handles
    recovery — see heartbeat.py.
  * Is every source still producing? That is SOURCE_FRESHNESS. Nothing recovers
    it automatically, because the cause is invariably outside this container
    (a sensor that lost write access to the shared log volume), and restarting
    the pipeline would only crash-loop it. Surfacing it as unhealthy is the
    whole remedy: it is the signal that was missing when cowrie.json and
    extra.json each went silent for over a week in 2026-08.

Exits 0 while both hold, 1 with the reason on stderr, which `docker inspect`
keeps in .State.Health.Log.
"""
import sys

import heartbeat
from ingestor import HEARTBEATS, SOURCE_FRESHNESS

rc = heartbeat.check(HEARTBEATS)

for name, max_age in SOURCE_FRESHNESS.items():
    seen = heartbeat.age(name)
    # None means the beat file is missing, which is a heartbeat-directory
    # problem rather than a quiet sensor — heartbeat.check() above already
    # reports that, and reporting it twice here would only obscure it.
    if seen is not None and seen > max_age:
        print(f"unhealthy: source '{name}' last produced a line "
              f"{seen / 3600:.1f}h ago (threshold {max_age / 3600:.1f}h)",
              file=sys.stderr)
        rc = 1

sys.exit(rc)
