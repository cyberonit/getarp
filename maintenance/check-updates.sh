#!/usr/bin/env bash
# Run from the project root: bash maintenance/check-updates.sh [check|apply|commit]
#
# Stages:
#   check   (default) dry-run — report outdated deps, change nothing
#   apply   update requirements pins + npm packages, pull latest base images
#   commit  rebuild images (make build), refresh Suricata rules (make rules),
#           then commit + push the dependency changes from the apply stage
set -euo pipefail

STAGE="${1:-check}"
case "$STAGE" in
    check|--check)   STAGE=check ;;
    apply|--apply)   STAGE=apply ;;
    commit|--commit) STAGE=commit ;;
    *) echo "usage: $0 [check|apply|commit]" >&2; exit 1 ;;
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

# ── Stage: commit ─────────────────────────────────────────────────────────────
# Rebuild with the updated deps, refresh IDS rules, then commit + push. Only
# the files the apply stage edits are committed, so unrelated work in the
# tree never gets swept into a maintenance commit.
if [[ "$STAGE" == "commit" ]]; then
    hdr "Rebuild images (make build)"
    make build
    ok "Images rebuilt — recreate containers with 'make up' to deploy them"

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
    echo "Done. Recreate containers to deploy the rebuilt images: make up"
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

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "────────────────────────────────────────"
if $APPLY; then
    echo "Apply stage done. Next: bash maintenance/check-updates.sh commit"
    echo "  (rebuilds images, refreshes Suricata rules, commits + pushes pins)"
else
    echo "Check stage complete. Next stages:"
    echo "  bash maintenance/check-updates.sh apply    # update pins/npm, pull bases"
    echo "  bash maintenance/check-updates.sh commit   # make build, make rules, git commit+push"
fi
echo "────────────────────────────────────────"
