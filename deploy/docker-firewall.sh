#!/usr/bin/env bash
# getarp.net — make UFW's intent real for Docker-published ports.
#
# Docker inserts its DNAT/forward rules ahead of UFW, so container-published
# ports on 0.0.0.0 are reachable from the internet regardless of the UFW
# allowlist (Docker traffic is FORWARDed, UFW filters INPUT). This installs a
# default-deny in the DOCKER-USER chain that only permits the ports the sensor
# is meant to expose, and drops any other external->container connection.
#
# Scope & safety:
#   * IPv4 only. IPv6 has no Docker kernel DNAT on this host; inbound v6 rides
#     the userland docker-proxy through INPUT, where UFW already applies.
#   * The jump is scoped to the external interface ($EXT_IF), so container<->
#     container traffic and container egress are untouched. RELATED,ESTABLISHED
#     is returned first so replies to container-initiated connections survive.
#   * Management SSH is a host process (INPUT chain), never DOCKER-USER, so this
#     cannot lock the operator out.
#
# Idempotent. Usage: docker-firewall.sh apply | down | status
set -euo pipefail

EXT_IF="${EXT_IF:-eth0}"
CHAIN="GETARP-DOCKER-FW"
# Ports the sensor intentionally exposes to the internet (published/original
# dst ports, matched pre-DNAT via conntrack --ctorigdstport):
#   22 cowrie ssh · 21 ftp · 23 telnet · 80/8081 http · 443 dashboard ·
#   3306 mysql · 6379 redis
PUBLIC_PORTS="${PUBLIC_PORTS:-22 21 23 80 443 3306 6379 8081}"

require_root() { [[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }; }

apply() {
    require_root
    # (Re)build our chain from scratch so re-runs are idempotent.
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"

    # Return traffic for container-initiated connections (egress replies) MUST
    # pass, or enrichment API calls / image pulls / ACME break.
    iptables -A "$CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
    iptables -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP
    # Permit Path-MTU / fragmentation-needed so egress large packets work.
    iptables -A "$CHAIN" -p icmp --icmp-type fragmentation-needed -j RETURN

    for p in $PUBLIC_PORTS; do
        iptables -A "$CHAIN" -p tcp -m conntrack --ctstate NEW \
                 --ctorigdstport "$p" -j RETURN
    done
    iptables -A "$CHAIN" -j DROP

    # Enter our chain only for new external-interface traffic; idempotent.
    iptables -C DOCKER-USER -i "$EXT_IF" -j "$CHAIN" 2>/dev/null \
        || iptables -I DOCKER-USER -i "$EXT_IF" -j "$CHAIN"
    echo "[docker-firewall] applied: $EXT_IF -> $CHAIN, public ports: $PUBLIC_PORTS"
}

down() {
    require_root
    iptables -D DOCKER-USER -i "$EXT_IF" -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "[docker-firewall] removed"
}

status() {
    require_root
    echo "== DOCKER-USER =="; iptables -L DOCKER-USER -n -v --line-numbers
    echo "== $CHAIN =="; iptables -L "$CHAIN" -n -v --line-numbers 2>/dev/null \
        || echo "(chain absent)"
}

case "${1:-apply}" in
    apply)  apply ;;
    down)   down ;;
    status) status ;;
    *) echo "usage: $0 apply|down|status" >&2; exit 2 ;;
esac
