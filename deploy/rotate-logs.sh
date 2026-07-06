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

command -v docker >/dev/null || exit 0
VOL=$(docker volume ls -q --filter name=honeypot_logs | head -1)
[[ -n "$VOL" ]] || exit 0
DIR=$(docker volume inspect -f '{{.Mountpoint}}' "$VOL")
[[ -d "$DIR" ]] || exit 0

STAMP=$(date +%F)

rotate() {
    # rotate FILE — rename, recreate with the same owner, so the writer never
    # blocks. Ownership matters: Suricata chowns its logs to its run-as user
    # on reopen, which fails with EPERM if root owns the new file.
    local f="$DIR/$1" owner
    [[ -s "$f" ]] || return 0
    owner=$(stat -c '%u:%g' "$f")
    mv "$f" "$f.$STAMP"
    # recreate immediately so the pipeline's inode check finds the new file
    # and drains the renamed one
    touch "$f" && chown "$owner" "$f" && chmod 664 "$f"
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
