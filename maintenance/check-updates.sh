#!/usr/bin/env bash
# Run from the project root: bash maintenance/check-updates.sh [--apply]
set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[OUT]${NC}   $*"; }
info() { echo -e "        $*"; }
hdr()  { echo -e "\n==> $*"; }

# ── 1. Python packages ────────────────────────────────────────────────────────
hdr "Python packages (host pip)"
OUTDATED=$(pip list --outdated --format=columns 2>/dev/null | tail -n +3 || true)
if [[ -z "$OUTDATED" ]]; then
    ok "All Python packages are up to date"
else
    while IFS= read -r line; do warn "$line"; done <<< "$OUTDATED"
    echo
    echo "  Pinned in requirements files — check before upgrading:"
    grep -h "==" api/requirements.txt pipeline/requirements.txt | sort -u | while read -r pin; do
        pkg="${pin%%[=><[!]*}"
        if echo "$OUTDATED" | grep -qi "^${pkg} "; then
            info "  $pin  <-- outdated"
        fi
    done
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
        ok "requirements files updated — run 'make build' to rebuild containers"
    else
        echo
        echo "  Run with --apply to update version pins in requirements files."
        echo "  Then run: make build"
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
        ok "npm packages updated — run 'make build' to rebuild the frontend image"
    else
        echo
        echo "  Run with --apply to run 'npm update' inside the frontend container."
        echo "  Then run: make build"
    fi
fi

# ── 3. Docker base images ─────────────────────────────────────────────────────
hdr "Docker base images"
if $APPLY; then
    echo "Pulling latest base images..."
    docker compose pull
    ok "Base images updated — run 'make build' to rebuild with new bases"
else
    echo "  Run with --apply to pull latest Docker base images."
    echo "  Then run: make build"
fi

# ── 4. Suricata rules ─────────────────────────────────────────────────────────
hdr "Suricata IDS rules"
if $APPLY; then
    echo "Updating Suricata ET Open rules..."
    docker compose exec suricata suricata-update 2>/dev/null && \
        docker compose restart suricata && \
        ok "Suricata rules updated and service restarted" || \
        echo "  (Suricata container not running — skipped)"
else
    echo "  Run with --apply to pull latest Suricata ET Open rules."
    echo "  Or run: make rules"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "────────────────────────────────────────"
if $APPLY; then
    echo "Done. If packages were updated, run: make build"
else
    echo "Dry-run complete. Re-run with --apply to apply all updates."
fi
echo "────────────────────────────────────────"
