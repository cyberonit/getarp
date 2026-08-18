#!/usr/bin/env bash
# Normalize ownership and modes on the shared honeypot_logs volume.
#
# Run once by deploy/setup.sh, and by every rotation pass — before the rotation
# and again after it recreates the live files — so a volume created before this
# existed converges on the same layout as a fresh one. Idempotent and safe to
# run with the stack up.
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
# The fix has two halves, and BOTH are load-bearing:
#
#   1. A shared group plus the setgid bit. gid 999 (sensorlogs) owns the
#      directory and every file in it; setgid on the directory means every NEW
#      file inherits that group whatever the writer's umask or uid is — which is
#      the part that stops this drifting back. The readers are members of the
#      group (see the Dockerfiles), so they no longer depend on world-read.
#
#   2. Per-writer ownership. The sticky bit lets a process rename or unlink only
#      files it OWNS, and the check is on uid alone — group permissions do not
#      enter into it. Two of the three sensors rotate their own logs, so an
#      owner that does not match the writer breaks rotation specifically.
#      On 2026-08-08 cowrie.json was owned by uid 998 (Suricata's) while Cowrie
#      runs as 999: Cowrie could still append to the open handle, but its
#      midnight rename() failed with EPERM and its JSON logging died on the
#      spot. Ten days of SSH sessions went unrecorded. Fixing only the group
#      would have let it resume appending and then broken it again at the next
#      midnight — worse, because it looks fixed.
#
# The sticky bit itself stays: with several sensors writing one directory, it is
# what stops a compromised one unlinking another's log.
#
# Root on the host, no container and no Docker socket mounted anywhere — this
# runs from cron alongside rotate-logs.sh, which already works this way.
set -euo pipefail

SENSOR_GID="${SENSOR_GID:-999}"

# Which sensor writes which live log:
#
#   cowrie.json, cowrie.log — Cowrie self-rotates, so it must own these.
#   extra.json              — rotated by rotate-logs.sh, but services.py reopens
#                             it on write and must be able to recreate it.
#   eve.json, fast.log      — Suricata chowns these to its run-as user when it
#                             reopens on SIGHUP, which is EPERM unless it
#                             already owns them.
declare -A SERVICE_LOGS=(
    [cowrie]="cowrie.json cowrie.log"
    [extra-services]="extra.json"
    [suricata]="eve.json fast.log"
)

# Last-resort defaults, used only when the real uid cannot be read from a
# running container. These are what the images ship today; they are a floor to
# fall back to, NOT the source of truth.
declare -A UID_BUILTIN=(
    [cowrie]=999
    [extra-services]=10001
    [suricata]=998
)

# Setting one of these pins that service and skips the container lookup — an
# operator escape hatch, and what the tests use to stay hermetic.
declare -A UID_PIN=(
    [cowrie]="${COWRIE_UID:-}"
    [extra-services]="${EXTRA_UID:-}"
    [suricata]="${SURICATA_UID:-}"
)

# Both outages this volume has had stayed invisible for over a week, because the
# only alarm was a line on stderr and cron on this host has no mail spool to
# deliver it to. Send warnings to syslog as well, where they are retained and
# greppable (journalctl -t getarp-logs).
warn() {
    echo "getarp-logs: WARNING $*" >&2
    if command -v logger >/dev/null; then
        logger -t getarp-logs -p daemon.warning "$*" || true
    fi
}

writer_uid() {
    # writer_uid SERVICE — the uid the sensor is ACTUALLY running as, read from
    # the host's view of its process, falling back to the pinned constant.
    #
    # Asking the container beats hardcoding, because the number is not ours to
    # choose. Every sensor image declares its user by NAME, which Docker
    # resolves through the image's own /etc/passwd at start; cowrie/cowrie is
    # additionally an unpinned :latest tag that the monthly maintenance job
    # pulls unattended. The uid has already moved once this way (998 -> 999 in
    # a July 2026 pull) and locked Cowrie out of its own log for two weeks. A
    # constant here would be re-asserted with total confidence against a
    # writer that had moved out from under it, and the verification below —
    # which compares files to this same table — would report success while the
    # sensor was locked out.
    #
    # Read from /proc rather than `docker exec id`: the sensor images have no
    # shell (cowrie has neither sh nor id), and this needs no exec privileges
    # on the socket. The 4th field of Uid: is the fsuid, which is precisely
    # what the kernel stamps on files the process creates.
    local svc="$1" cid pid uid
    local builtin="${UID_BUILTIN[$svc]}" pin="${UID_PIN[$svc]}"

    if [[ -n "$pin" ]]; then
        _usable_uid "$pin" && { echo "$pin"; return; }
        warn "${svc^^}_UID=$pin is not a usable owner — falling back to $builtin"
        echo "$builtin"; return
    fi

    command -v docker >/dev/null || { echo "$builtin"; return; }
    cid=$(docker ps -q --filter "label=com.docker.compose.service=$svc" | head -1)
    [[ -n "$cid" ]] || { echo "$builtin"; return; }
    pid=$(docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null) || true
    [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/status" ]] \
        || { echo "$builtin"; return; }
    uid=$(awk '/^Uid:/{print $5}' "/proc/$pid/status")
    _usable_uid "$uid" || { echo "$builtin"; return; }

    # Drift is worth saying out loud even though it is handled: it means an
    # image changed its identity, which is the event that has broken this
    # volume twice.
    [[ "$uid" != "$builtin" ]] && \
        warn "$svc runs as uid $uid, not the expected $builtin — image identity changed; using $uid"
    echo "$uid"
}

_usable_uid() {
    # Numeric and not root. Root is rejected from BOTH the derived and the
    # pinned path: Suricata is root for the first moments of its life, so a
    # lookup can legitimately catch it at 0, and chowning its logs to root
    # would lock it out the instant it drops privileges. There is no case where
    # root is the right owner of a sensor log.
    [[ "$1" =~ ^[0-9]+$ && "$1" != "0" ]]
}

# HONEYPOT_LOG_DIR bypasses the volume lookup. It exists so this can be
# exercised against a throwaway directory — the tests do exactly that — without
# a run aimed at a fixture ever being able to touch the real volume. Unset in
# every real invocation, which resolves the mountpoint through Docker.
DIR="${HONEYPOT_LOG_DIR:-}"
if [[ -z "$DIR" ]]; then
    command -v docker >/dev/null || exit 0
    VOL=$(docker volume ls -q --filter name=honeypot_logs | head -1)
    [[ -n "$VOL" ]] || exit 0
    DIR=$(docker volume inspect -f '{{.Mountpoint}}' "$VOL")
fi
[[ -d "$DIR" ]] || exit 0

# Resolve each writer once, then key by filename for the passes below. Done
# here, after DIR, so a run that exits early for want of a volume never bothers
# inspecting containers.
declare -A LOG_OWNER=()
for svc in "${!SERVICE_LOGS[@]}"; do
    svc_uid=$(writer_uid "$svc")
    for log in ${SERVICE_LOGS[$svc]}; do
        LOG_OWNER[$log]="$svc_uid"
    done
done

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

# Hand each live log back to the sensor that writes it. Only the live files:
# rotated archives are pruned by rotate-logs.sh running as root, which the
# sticky bit does not restrict, and reassigning them would only make a
# compromised sensor able to erase its own history.
for name in "${!LOG_OWNER[@]}"; do
    f="$DIR/$name"
    [[ -e "$f" ]] || continue
    want="${LOG_OWNER[$name]}"
    have=$(stat -c '%u' "$f")
    [[ "$have" == "$want" ]] && continue
    chown "$want" "$f"
    echo "getarp-logs: $name reassigned from uid $have to uid $want"
done

# Verify rather than assume. A silent failure here is exactly the class of bug
# this script exists to prevent, so it has to be noisy to be worth anything.
rc=0
for name in "${!LOG_OWNER[@]}"; do
    f="$DIR/$name"
    [[ -e "$f" ]] || continue
    read -r u g m < <(stat -c '%u %g %a' "$f")
    [[ "$u" == "${LOG_OWNER[$name]}" && "$g" == "$SENSOR_GID" && "$m" == "664" ]] \
        || { warn "$name is $u:$g $m, expected ${LOG_OWNER[$name]}:$SENSOR_GID 664"
             rc=1; }
done

read -r dg dm < <(stat -c '%g %a' "$DIR")
[[ "$dg" == "$SENSOR_GID" && "$dm" == "3777" ]] \
    || { warn "$DIR is gid $dg mode $dm, expected gid $SENSOR_GID mode 3777"; rc=1; }

[[ $rc -eq 0 ]] && echo "getarp-logs: $DIR normalized to gid $SENSOR_GID, mode 3777 (setgid)"
exit $rc
