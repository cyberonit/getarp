#!/usr/bin/env python3
"""Container HEALTHCHECK for the analytics engine.

Run by Docker as `python /app/healthcheck.py`. Python is the one interpreter
guaranteed to exist in this image — there is no curl, no redis-cli — so the
check has no dependency the image does not already ship.

Exits 0 while every loop is beating, 1 (with the offending loop named on
stderr, which `docker inspect` keeps in .State.Health.Log) as soon as one is
not. Recovery is the watchdog's job, not this script's; see heartbeat.py.
"""
import sys

import heartbeat
from engine import HEARTBEATS

sys.exit(heartbeat.check(HEARTBEATS))
