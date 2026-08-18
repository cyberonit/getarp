#!/usr/bin/env bash
# Rotate honeypot sensor logs on the shared honeypot_logs volume.
# Installed to /etc/cron.daily/getarp-logs by deploy/setup.sh.
#
# Why not logrotate: the volume directory is world-writable with files owned by
# three different container uids — logrotate refuses world-writable parents,
# and create-mode ownership would have to guess container uids. This script
# runs as root and sidesteps all of that.
#
# What rotates what:
#   eve.json, fast.log  — rotated here; Suricata reopens its logs on SIGHUP.
#   extra.json          — rotated here; services.py reopens per write.
#   cowrie.json         — Cowrie self-rotates daily (cowrie.json.YYYY-MM-DD);
#                         we only compress + prune what it leaves behind.
#   cowrie.log          — rotated here, by copy-and-truncate. Cowrie does NOT
#                         rotate this one (it had grown to 250 MB unrotated by
#                         2026-08) and holds the handle open for the life of the
#                         process with no reopen signal, so renaming it would
#                         just send every subsequent line to an unlinked inode.
# The pipeline tails by inode and drains the renamed file before reopening,
# so rotation does not drop events (see pipeline/ingestor.py tail()).
set -euo pipefail

KEEP_DAYS="${KEEP_DAYS:-14}"    # compressed raw logs kept for forensics;
                                # postgres is the system of record (1y retention)

# Shared group for sensor-written logs. Every writer either runs with this gid
# (cowrie 999:999, extra-services 10001:999) or runs as root (suricata), so
# group-write at 664 is sufficient and the volume needs no world-writable files.
SENSOR_GID="${SENSOR_GID:-999}"

# Warnings go to syslog as well as stderr: cron on this host has no mail spool,
# so a bare stderr line is discarded and every alarm this script raises would be
# lost — which is how two multi-day sensor outages went unnoticed.
warn() {
    echo "getarp-logs: WARNING $*" >&2
    if command -v logger >/dev/null; then
        logger -t getarp-logs -p daemon.warning "$*" || true
    fi
}

command -v docker >/dev/null || exit 0
VOL=$(docker volume ls -q --filter name=honeypot_logs | head -1)
[[ -n "$VOL" ]] || exit 0
DIR=$(docker volume inspect -f '{{.Mountpoint}}' "$VOL")
[[ -d "$DIR" ]] || exit 0

STAMP=$(date +%F)

normalize() {
    # Converge the volume on the shared-group layout: setgid directory, gid
    # $SENSOR_GID, mode 664, and each live log owned by the sensor that writes
    # it. All of that policy lives in fix-log-perms.sh so there is one place to
    # change it; this is just the call. Installed to /usr/local/bin by setup.sh
    # because cron runs this script from /etc/cron.daily, away from the repo.
    #
    # Non-fatal: rotation still has to happen even if normalization does not.
    local _fixperms
    for _fixperms in /usr/local/bin/getarp-fix-log-perms \
                     "$(dirname "$0")/fix-log-perms.sh"; do
        [[ -x "$_fixperms" ]] || continue
        SENSOR_GID="$SENSOR_GID" bash "$_fixperms" || \
            warn "permission normalization failed ($_fixperms)"
        return 0
    done
    warn "fix-log-perms.sh not found — volume permissions were not normalized"
}

# Before touching anything, so the sensors are writing where they should and a
# volume that predates this converges. Also covers cowrie.json, which nothing
# here rotates.
normalize

rotate() {
    # rotate FILE — rename, then recreate it so the writer never blocks.
    #
    # Ownership and mode are set by the normalize() pass that follows, not here:
    # the pre-rotation owner is NOT a reliable guide to who actually writes the
    # file (extra.json was owned by uid 998 while extra-services runs as 10001,
    # which silently locked it out of its own log twice). Preserving the owner
    # on the recreate is only a fallback for the case where normalize() cannot
    # run — root-owned would lock out every sensor, which is strictly worse.
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
}

copytruncate() {
    # copytruncate FILE — for a writer that holds the handle open forever and
    # has no way to be told to reopen. Copy the contents aside, then truncate
    # the original in place so the existing file descriptor stays valid and
    # keeps appending at offset 0.
    #
    # The window between the copy and the truncate can lose a line or two. That
    # is the accepted cost of rotating a log whose writer cannot reopen, and it
    # applies only to cowrie.log, which is human-readable output — the pipeline
    # ingests cowrie.json, not this file, so nothing downstream is affected.
    local f="$DIR/$1" target
    [[ -s "$f" ]] || return 0
    target="$f.$STAMP"
    [[ -e "$target" || -e "$target.gz" ]] && target="$f.$STAMP-$(date +%H%M%S)"
    cp -p "$f" "$target" || { warn "could not copy $1 aside; not truncating"; return 0; }
    : > "$f"
}

rotate eve.json
rotate fast.log
rotate extra.json
copytruncate cowrie.log

# Put the freshly recreated files back under the right owner, group and mode
# before anyone tries to write to them. This is the pass that matters: rotate()
# above deliberately does the minimum, and a sensor that cannot open its own
# recreated log is exactly the failure this whole script guards against.
normalize

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
