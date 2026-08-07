#!/usr/bin/env bash
# Rotate honeypot sensor logs on the shared honeypot_logs volume.
# Installed to /etc/cron.daily/getarp-logs by deploy/setup.sh.
#
# Why not logrotate: the volume directory is mode 1777 with files owned by
# three different container uids — logrotate refuses world-writable parents,
# and create-mode ownership would have to guess container uids. This script
# runs as root and sidesteps all of that.
#
# What rotates what:
#   eve.json, fast.log  — rotated here; Suricata reopens its logs on SIGHUP.
#   extra.json          — rotated here; services.py reopens per write.
#   cowrie.json, cowrie.log — Cowrie self-rotates daily (cowrie.json.YYYY-MM-DD);
#                             we only compress + prune its rotated files.
# The pipeline tails by inode and drains the renamed file before reopening,
# so rotation does not drop events (see pipeline/ingestor.py tail()).
set -euo pipefail

KEEP_DAYS="${KEEP_DAYS:-14}"    # compressed raw logs kept for forensics;
                                # postgres is the system of record (3y retention)

# Shared group for sensor-written logs. Every writer either runs with this gid
# (cowrie 999:999, extra-services 10001:999) or runs as root (suricata), so
# group-write at 664 is sufficient and the volume needs no world-writable files.
SENSOR_GID="${SENSOR_GID:-999}"

command -v docker >/dev/null || exit 0
VOL=$(docker volume ls -q --filter name=honeypot_logs | head -1)
[[ -n "$VOL" ]] || exit 0
DIR=$(docker volume inspect -f '{{.Mountpoint}}' "$VOL")
[[ -d "$DIR" ]] || exit 0

STAMP=$(date +%F)

# Converge the volume on the shared-group layout before touching anything:
# setgid directory, gid $SENSOR_GID and mode 664 on every live file. Cheap and
# idempotent, and it covers the files this script does NOT rotate — cowrie.json
# and cowrie.log, which Cowrie rotates itself and therefore recreates with its
# own umask, outside anything here. Installed to /usr/local/bin by setup.sh
# because cron runs this script from /etc/cron.daily, away from the repo.
# Non-fatal: rotation still has to happen even if normalization does not.
for _fixperms in /usr/local/bin/getarp-fix-log-perms \
                 "$(dirname "$0")/fix-log-perms.sh"; do
    [[ -x "$_fixperms" ]] || continue
    SENSOR_GID="$SENSOR_GID" bash "$_fixperms" || \
        echo "getarp-logs: WARNING permission normalization failed" >&2
    break
done

rotate() {
    # rotate FILE — rename, then recreate it writable by the sensor that owns
    # the stream, so the writer never blocks.
    #
    # Group is what makes this work, and it must be set explicitly: the
    # pre-rotation owner is NOT a reliable guide to who actually writes the
    # file. extra.json was owned by uid 998 while extra-services runs as 10001,
    # so preserving owner alone and using 664 silently locked it out of its own
    # log (2026-08-06). Forcing SENSOR_GID covers every writer at 664 instead
    # of reaching for a world-writable 666, which would let any one compromised
    # sensor container tamper with the other sensors' logs.
    #
    # Owner is still preserved because Suricata chowns its logs to its run-as
    # user on reopen, which fails with EPERM if root owns the new file.
    local f="$DIR/$1" owner target
    [[ -s "$f" ]] || return 0
    target="$f.$STAMP"
    # A second run on the same day (manual test, cron retry) collides: gzip
    # will not overwrite the existing archive, orphaning an uncompressed file
    # that the *.gz prune below never reclaims. Uniquify rather than clobber.
    [[ -e "$target" || -e "$target.gz" ]] && target="$f.$STAMP-$(date +%H%M%S)"
    owner=$(stat -c '%u' "$f")
    mv "$f" "$target"
    # recreate immediately so the pipeline's inode check finds the new file
    # and drains the renamed one
    touch "$f" && chown "$owner:$SENSOR_GID" "$f" && chmod 664 "$f"
    # Fail loudly rather than silently losing a sensor: both outages this
    # volume has had were invisible until someone went looking.
    [[ "$(stat -c '%g %a' "$f")" == "$SENSOR_GID 664" ]] \
        || echo "getarp-logs: WARNING $f is $(stat -c '%U:%G %a' "$f"), expected gid $SENSOR_GID mode 664" >&2
}

rotate eve.json
rotate fast.log
rotate extra.json

# Suricata keeps writing to the renamed inode until told to reopen
SURICATA=$(docker ps -q --filter name=suricata | head -1)
[[ -n "$SURICATA" ]] && docker kill -s HUP "$SURICATA" >/dev/null 2>&1 || true

# let the pipeline drain the renamed files before compressing them away
sleep 10

# compress today's rotations and cowrie's own daily rotations (skip live files)
find "$DIR" -maxdepth 1 -type f \
    \( -name 'eve.json.*' -o -name 'fast.log.*' -o -name 'extra.json.*' \
       -o -name 'cowrie.json.2*' -o -name 'cowrie.log.2*' \) \
    ! -name '*.gz' -exec gzip -q {} + 2>/dev/null || true

# prune old archives
find "$DIR" -maxdepth 1 -type f -name '*.gz' -mtime "+$KEEP_DAYS" -delete
