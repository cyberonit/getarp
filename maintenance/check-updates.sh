#!/usr/bin/env bash
# Run from the project root: bash maintenance/check-updates.sh [check|apply|commit|rules]
#
# Stages:
#   check   (default) dry-run — report outdated deps, change nothing
#   apply   update requirements pins + npm packages, pull latest base images,
#           reclaim images/build cache older than 30 days
#   commit  rebuild + deploy images (make up), refresh Suricata rules
#           (make rules), then commit + push the dependency changes from
#           the apply stage
#   rules   refresh Suricata rules only — ET Open publishes daily, so the
#           weekly cron runs this between monthly full-maintenance passes
set -euo pipefail

STAGE="${1:-check}"
case "$STAGE" in
    check|--check)   STAGE=check ;;
    apply|--apply)   STAGE=apply ;;
    commit|--commit) STAGE=commit ;;
    rules|--rules)   STAGE=rules ;;
    *) echo "usage: $0 [check|apply|commit|rules]" >&2; exit 1 ;;
esac
APPLY=false
[[ "$STAGE" == "apply" ]] && APPLY=true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; NC=''
fi
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[OUT]${NC}   $*"; }
info() { echo -e "        $*"; }
hdr()  { echo -e "\n==> $*"; }

update_suricata_rules() {
    hdr "Suricata IDS rules (make rules)"
    if ! docker compose ps --status running suricata 2>/dev/null | grep -q suricata; then
        echo "  (Suricata container not running — skipped)"
        return 0
    fi
    echo "Updating Suricata ET Open rules..."
    # refresh the rule-source index first; non-fatal, the cached index works
    docker compose exec -T suricata suricata-update update-sources \
        || warn "could not refresh rule-source index — continuing with cached copy"
    # -o writes the merged ruleset where suricata.yaml actually reads it
    # (/etc/suricata/rules, bind-mounted); the suricata-update default of
    # /var/lib/suricata/rules is unmounted and never loaded.
    # --no-reload: the unix-command socket is disabled, we restart instead.
    if docker compose exec -T suricata suricata-update -o /etc/suricata/rules --no-reload; then
        docker compose restart suricata
        ok "Suricata rules updated and service restarted"
    else
        warn "suricata-update failed — see errors above; rules NOT updated"
    fi
}

# ── Stage: rules ──────────────────────────────────────────────────────────────
if [[ "$STAGE" == "rules" ]]; then
    update_suricata_rules
    exit 0
fi

# ── Stage: commit ─────────────────────────────────────────────────────────────
# Rebuild with the updated deps, refresh IDS rules, then commit + push. Only
# the files the apply stage edits are committed, so unrelated work in the
# tree never gets swept into a maintenance commit.
if [[ "$STAGE" == "commit" ]]; then
    hdr "Rebuild and deploy images (make up)"
    make up
    ok "Images rebuilt and containers recreated on them"

    update_suricata_rules

    hdr "Commit dependency updates"
    DEP_FILES=(api/requirements.txt pipeline/requirements.txt
               frontend/package.json frontend/package-lock.json)
    CHANGED=()
    for f in "${DEP_FILES[@]}"; do
        if [[ -f "$f" ]] && ! git diff --quiet -- "$f"; then
            CHANGED+=("$f")
        fi
    done
    if [[ ${#CHANGED[@]} -eq 0 ]]; then
        ok "No dependency changes to commit"
    else
        git add -- "${CHANGED[@]}"
        git commit -m "Maintenance: dependency updates $(date +%Y-%m-%d)"
        git push
        ok "Committed and pushed: ${CHANGED[*]}"
    fi

    echo
    echo "────────────────────────────────────────"
    echo "Done. Images rebuilt and deployed, Suricata rules refreshed."
    echo "────────────────────────────────────────"
    exit 0
fi

# ── 1. Python packages ────────────────────────────────────────────────────────
hdr "Python packages"
PINNED_OUT=$(grep -h "==" api/requirements.txt pipeline/requirements.txt | sort -u | while read -r pin; do
    pkg="${pin%%[=><[![:space:]]*}"
    pinned_ver="${pin#*==}"; pinned_ver="${pinned_ver%%[[:space:]#]*}"
    latest_ver=$(pip index versions "$pkg" 2>/dev/null | grep -oP 'Available versions: \K[^,]+' || true)
    if [[ -n "$latest_ver" ]]; then
        oldest=$(printf '%s\n%s\n' "$pinned_ver" "$latest_ver" | sort -V | head -1)
        if [[ "$oldest" == "$pinned_ver" && "$pinned_ver" != "$latest_ver" ]]; then
            echo "${pkg}==${pinned_ver}  →  ${latest_ver}"
        fi
    fi
done)
if [[ -z "$PINNED_OUT" ]]; then
    ok "All pinned packages are up to date"
else
    while IFS= read -r line; do warn "$line"; done <<< "$PINNED_OUT"
    if $APPLY; then
        echo
        echo "Applying upgrades to pinned requirements files..."
        for req in api/requirements.txt pipeline/requirements.txt; do
            echo "  Updating $req"
            # Re-pin each package to the latest available version, preserving comments
            while IFS= read -r line; do
                # Skip comments and blank lines
                if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "${line// }" ]]; then
                    echo "$line"
                    continue
                fi
                pkg="${line%%[=><[!#]*}"
                pkg="${pkg%%[[:space:]]*}"
                if [[ -z "$pkg" ]]; then echo "$line"; continue; fi
                latest=$(pip index versions "$pkg" 2>/dev/null | grep -oP 'Available versions: \K[^,]+' || true)
                if [[ -n "$latest" ]]; then
                    comment=$(echo "$line" | grep -oP '#.*' || true)
                    if [[ -n "$comment" ]]; then
                        echo "${pkg}==${latest}          ${comment}"
                    else
                        echo "${pkg}==${latest}"
                    fi
                else
                    echo "$line"
                fi
            done < "$req" > "${req}.tmp" && mv "${req}.tmp" "$req"
        done
        ok "requirements files updated"
    else
        echo
        echo "  Run the apply stage to update the version pins."
    fi
fi

# ── 2. Frontend npm packages ──────────────────────────────────────────────────
hdr "Frontend npm packages (via Docker)"
if ! docker compose ps --services 2>/dev/null | grep -q .; then
    echo "  (stack not running — checking via temporary container)"
fi

NPM_OUT=$(docker compose run --rm --no-deps frontend npm outdated 2>/dev/null || true)
if [[ -z "$NPM_OUT" ]]; then
    ok "All npm packages are up to date"
else
    while IFS= read -r line; do warn "$line"; done <<< "$NPM_OUT"
    if $APPLY; then
        echo
        echo "Applying npm updates..."
        docker compose run --rm --no-deps frontend npm update
        ok "npm packages updated"
    else
        echo
        echo "  Run the apply stage to run 'npm update' inside the frontend container."
    fi
fi

# ── 3. Docker base images ─────────────────────────────────────────────────────
hdr "Docker base images"
if $APPLY; then
    echo "Pulling latest base images..."
    docker compose pull
    ok "Base images updated"
else
    echo "  Run the apply stage to pull the latest Docker base images."
fi

# ── 3b. Sensor identity (uid drift across a pull) ─────────────────────────────
# The sensor images declare their user by NAME, which Docker resolves through
# the image's own /etc/passwd at start. cowrie/cowrie is additionally an
# unpinned :latest tag — no versioned tags exist upstream — so this stage can
# change the numeric uid a sensor runs as, unattended, on the monthly cron.
#
# That has happened: a July 2026 pull moved Cowrie 998 -> 999 and locked it out
# of its own log on the shared honeypot_logs volume for two weeks, silently.
# deploy/fix-log-perms.sh now derives the uid from the running container rather
# than trusting a constant, so a drift is *survived* — but it is still worth
# announcing, because it changes on-disk ownership across the whole volume and
# is invisible in the compose file.
#
# Reads /etc/passwd out of the image without running it: `docker create` makes
# a container without starting it, and `docker cp` streams the file out. The
# sensor images ship no shell (cowrie has neither sh nor id), so exec is not an
# option here.
image_user_uid() {
    # image_user_uid IMAGE — numeric uid the image's declared USER resolves to.
    local image="$1" user cid uid
    user=$(docker image inspect -f '{{.Config.User}}' "$image" 2>/dev/null) || return 1
    user="${user%%:*}"
    [[ -n "$user" ]] || { echo 0; return 0; }          # no USER directive -> root
    [[ "$user" =~ ^[0-9]+$ ]] && { echo "$user"; return 0; }   # already numeric
    cid=$(docker create "$image" 2>/dev/null) || return 1
    uid=$(docker cp "$cid:/etc/passwd" - 2>/dev/null \
          | tar -xO 2>/dev/null \
          | awk -F: -v u="$user" '$1==u {print $3; exit}')
    docker rm -f "$cid" >/dev/null 2>&1 || true
    [[ -n "$uid" ]] || return 1
    echo "$uid"
}

running_uid() {
    # running_uid SERVICE — uid the container is actually running as right now.
    # 4th field of Uid: is the fsuid, which is what the kernel stamps on files.
    local svc="$1" cid pid
    cid=$(docker ps -q --filter "label=com.docker.compose.service=$svc" | head -1)
    [[ -n "$cid" ]] || return 1
    pid=$(docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null) || return 1
    [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/status" ]] || return 1
    awk '/^Uid:/{print $5; exit}' "/proc/$pid/status"
}

hdr "Sensor identity (uid drift)"
SENSOR_DRIFT=false
for svc in cowrie suricata extra-services; do
    # The image REFERENCE the service was started from (e.g. cowrie/cowrie:latest),
    # not the image ID it happens to be running. Resolving that reference now
    # picks up whatever the pull above just fetched, which is the comparison
    # that matters: what the container is versus what the next deploy gives it.
    cid=$(docker ps -q --filter "label=com.docker.compose.service=$svc" | head -1)
    if [[ -z "$cid" ]]; then
        info "$svc: not running, skipped"
        continue
    fi
    img=$(docker inspect -f '{{.Config.Image}}' "$cid" 2>/dev/null) || img=""
    if [[ -z "$img" ]]; then
        info "$svc: image not resolvable, skipped"
        continue
    fi
    want=$(image_user_uid "$img" 2>/dev/null) || want=""
    have=$(running_uid "$svc" 2>/dev/null) || have=""
    if [[ -z "$want" || -z "$have" ]]; then
        info "$svc: could not determine uid (image=${want:-?} running=${have:-?})"
    elif [[ "$want" == "0" ]]; then
        # The image declares no USER (or declares root), so it tells us nothing
        # about the runtime identity: the process drops privileges itself after
        # start. Suricata does exactly this — it launches as root and becomes
        # its --user, so "image says 0, running as 998" is the healthy steady
        # state, not drift. Nothing to compare against; just report it.
        info "$svc: image declares no user, drops privileges at runtime (now $have)"
    elif [[ "$want" == "$have" ]]; then
        ok "$svc runs as uid $have, image agrees"
    else
        SENSOR_DRIFT=true
        warn "$svc UID DRIFT: running as $have, image $img resolves to $want"
    fi
done
if $SENSOR_DRIFT; then
    echo
    info "The next deploy will move a sensor to a different uid. Ownership on the"
    info "honeypot_logs volume follows the writer automatically (fix-log-perms.sh"
    info "derives it), but run it right after 'make up' to converge immediately:"
    info "  bash /usr/local/bin/getarp-fix-log-perms"
    info "Then confirm ingest with a per-sensor count, not a total:"
    info "  SELECT sensor, count(*), max(ts) FROM events"
    info "  WHERE ts > now() - interval '10 minutes' GROUP BY 1;"
fi

# ── 4. Docker disk reclaim ────────────────────────────────────────────────────
# Images and build cache are the largest single consumer of disk on this box —
# larger than the database itself (measured 2026-08-07: 7.1 GB of reclaimable
# images plus 2.5 GB of build cache, against a ~7.4 GB projected 1-year DB).
# Every monthly rebuild orphans another layer set, so this needs to run on the
# same cadence as the rebuild that creates the garbage.
#
# until=720h (30 days) deliberately keeps recent images so a rollback to last
# month's build is still possible; anything older is assumed superseded.
# Images backing running containers are never removed by prune. Volumes are
# NEVER pruned here — they hold the database.
hdr "Docker disk reclaim"
if $APPLY; then
    echo "Reclaiming images and build cache older than 30 days..."
    docker image prune -af --filter "until=720h"   || warn "image prune failed"
    docker builder prune -af --filter "until=720h" || warn "builder prune failed"
    ok "Docker disk reclaimed"
    docker system df
else
    docker system df
    echo "  Run the apply stage to reclaim images/build cache older than 30 days."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "────────────────────────────────────────"
if $APPLY; then
    echo "Apply stage done. Next: bash maintenance/check-updates.sh commit"
    echo "  (rebuilds + deploys images, refreshes Suricata rules, commits + pushes pins)"
else
    echo "Check stage complete. Next stages:"
    echo "  bash maintenance/check-updates.sh apply    # update pins/npm, pull bases, reclaim disk"
    echo "  bash maintenance/check-updates.sh commit   # make up, make rules, git commit+push"
fi
echo "────────────────────────────────────────"
