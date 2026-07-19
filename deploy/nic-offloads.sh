#!/usr/bin/env bash
# getarp.net — disable NIC offloads that break Suricata packet capture.
#
# The kernel/NIC merges received TCP segments into super-packets (GRO, and on
# virtio_net also hardware GRO via rx-gro-hw) and hands the capture path
# frames far larger than the wire MTU. Suricata's AF_PACKET snaplen is sized
# to the MTU, so merged frames arrive truncated ("SURICATA AF-PACKET truncated
# packet") and payload/content matching silently misses on exactly the flows
# that matter. Segmentation offloads (TSO/GSO) do the same on the transmit
# side for any future tap use, so they are disabled too.
#
# Idempotent; features the driver reports as [fixed] are skipped with a note.
# Usage: nic-offloads.sh [iface]   (default: $EXT_IF, else eth0)
set -euo pipefail

IFACE="${1:-${EXT_IF:-eth0}}"
FEATURES="gro rx-gro-hw lro tso gso"

for f in $FEATURES; do
    if ethtool -K "$IFACE" "$f" off 2>/dev/null; then
        echo "[✓] $IFACE: $f off"
    else
        # [fixed] features can't be toggled; anything else is worth seeing
        echo "[!] $IFACE: could not disable $f (driver may report it fixed)"
    fi
done
