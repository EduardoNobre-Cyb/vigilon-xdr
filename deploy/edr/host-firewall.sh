#!/usr/bin/env bash
# Lock down vboxnet0 so agent VMs can ONLY reach the backend on port 5000
# Usage: sudo bash deploy/edr/host-firewall.sh [up|down]

set -euo pipefail

IFACE="vboxnet0"
BACKEND_PORT="5000"

case "${1:-up}" in
  up)
    # Flush any old rules for this interface
    iptables -D INPUT -i "$IFACE" -p tcp --dport "$BACKEND_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$IFACE" -j DROP 2>/dev/null || true

    # Allow agent → backend traffic on port 5000 only
    iptables -A INPUT -i "$IFACE" -p tcp --dport "$BACKEND_PORT" -j ACCEPT

    # Drop everything else from the VMs (scans, pivots, other services)
    iptables -A INPUT -i "$IFACE" -j DROP

    echo "vboxnet0 locked: only tcp/$BACKEND_PORT allowed from VMs."
    echo "Verify with: sudo iptables -L INPUT -n -v | grep vboxnet0"
    ;;

  down)
    iptables -D INPUT -i "$IFACE" -p tcp --dport "$BACKEND_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i "$IFACE" -j DROP 2>/dev/null || true
    echo "vboxnet0 firewall rules removed."
    ;;

  *)
    echo "Usage: $0 [up|down]" >&2
    exit 1
    ;;
esac