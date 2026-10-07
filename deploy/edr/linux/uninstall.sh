#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this with sudo." >&2
    exit 1
fi

systemctl disable --now vigilon-edr 2>/dev/null || true
rm -f /etc/systemd/system/vigilon-edr.service
systemctl daemon-reload
systemctl reset-failed vigilon-edr 2>/dev/null || true

if [[ -f /etc/audit/rules.d/vigilon-edr.rules ]]; then
    rm -f /etc/audit/rules.d/vigilon-edr.rules
    augenrules --load || true
fi

echo "Vigilon EDR service removed."