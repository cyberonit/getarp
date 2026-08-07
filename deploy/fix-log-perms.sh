#!/usr/bin/env bash
# Normalize ownership and modes on the shared honeypot_logs volume.
#
# Run once by deploy/setup.sh and again at the top of every rotation pass, so a
# volume created before this existed converges on the same layout as a fresh
# one. Idempotent and safe to run with the stack up.
#
# WHY THIS IS NEEDED
# Three sensors write this volume as three different uids (cowrie 999,
# extra-services 10001, suricata 998 after it drops privileges) and two
# consumers read it (pipeline, api) as a fourth. Nothing lines those numbers up
# by itself, so the volume ran as mode 1777 — world-writable — with the readers
# getting in purely through the world-read bit on 0664 files. That works only
# while every writer's umask stays at 0022: a sensor that creates its log 0640
# (an upstream image change, a fresh eve.json after a SIGHUP reopen, cowrie's
# own daily rotation) locks the pipeline out silently. No crash, no error, just
# a tail that never sees another line.
#
# The fix is a shared group plus the setgid bit:
#   * gid 999 (sensorlogs) owns the directory and every file in it;
#   * setgid on the directory means every NEW file inherits that group whatever
#     the writer's umask or uid is — which is the part that stops this drifting
#     back. The readers are members of the group (see the Dockerfiles), so they
#     no longer depend on world-read.
# The sticky bit stays: with several sensors writing one directory, it is what
# stops a compromised one unlinking another's log.
#
# Root on the host, no container and no Docker socket mounted anywhere — this
# runs from cron alongside rotate-logs.sh, which already works this way.
set -euo pipefail

SENSOR_GID="${SENSOR_GID:-999}"

command -v docker >/dev/null || exit 0
VOL=$(docker volume ls -q --filter name=honeypot_logs | head -1)
[[ -n "$VOL" ]] || exit 0
DIR=$(docker volume inspect -f '{{.Mountpoint}}' "$VOL")
[[ -d "$DIR" ]] || exit 0

# 3777 = setgid + sticky + rwxrwxrwx. The setgid bit is the point of this
# script; the world-write bit is inherited from the previous 1777 and has to
# stay, because Suricata cannot be made a member of the sensor group: it starts
# as root and drops to its own uid via setgroups(), which discards any
# supplementary group the container was given (`Groups:` is empty in
# /proc/<suricata>/status, with or without group_add). It therefore needs
# "other" write to create eve.json and fast.log on a fresh volume.
#
# That is not a regression — it is exactly today's posture — and the sticky bit
# still stops one sensor unlinking another's log. What changes is that the
# group is no longer left to chance.
chgrp "$SENSOR_GID" "$DIR"
chmod 3777 "$DIR"

# Existing files predate the setgid bit and keep whatever group they were
# created with; the group-write bit matters because rotation recreates these
# files under the writer's own uid.
find "$DIR" -maxdepth 1 -type f -exec chgrp "$SENSOR_GID" {} +
find "$DIR" -maxdepth 1 -type f ! -name '*.gz' -exec chmod 664 {} +
find "$DIR" -maxdepth 1 -type f -name '*.gz' -exec chmod 640 {} +

echo "getarp-logs: $DIR normalized to gid $SENSOR_GID, mode 3777 (setgid)"
