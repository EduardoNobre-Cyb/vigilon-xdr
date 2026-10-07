#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this with sudo." >&2
    exit 1
fi

AGENT_DIR="$(realpath "${1:-$(dirname "$0")/../../..}")"
PYTHON="${PYTHON:-$AGENT_DIR/venv/bin/python3}"
CONF_DIR=/etc/vigilon-edr
ENV_FILE="$CONF_DIR/agent.env"
UNIT_FILE=/etc/systemd/system/vigilon-edr.service
AUDIT_RULES=/etc/audit/rules.d/vigilon-edr.rules
AGENT_SCRIPT="$AGENT_DIR/agents/endpoint_agent/linux_agent.py"

if [[ ! -f "$AGENT_SCRIPT" ]]; then
    echo "Can't ffind $AGENT_SCRIPT. Pass the project folder as the first argument." >&2
    exit 1
fi
if [[ ! -x "$PYTHON" ]]; then
    echo "Can't find Python at $PYTHON. Run again with PYTHON=/path/to/python3 sudo -E ./install.sh" >&2
    exit 1
fi

mkdir -p "$CONF_DIR"
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<CONF
# Vigilon EDR agent settings. After editing: sudo systemctl restart vigilon-edr
BACKEND_URL=http://192.168.56.1:5000
EDR_MODEL_DIR=$AGENT_DIR/data/models/EDR
PROCESS_COLLECTOR=auditd
ML_FIRST_MODE=true
ML_EVENT_MIN_SCORE=0.70
TELEMETRY_POLL_INTERVAL=0.25
CONF
    chmod 600 "$ENV_FILE"
    echo "Created $ENV_FILE"
else
    echo "Keeping your existing $ENV_FILE"
fi

cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=Vigilon EDR Sensor
Wants=network-online.target
After=network-online.target vboxadd-service.service auditd.service
# Never give up restarting (the default stops after 5 quick failures)
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
Environment=PYTHONPATH=$AGENT_DIR
Environment=PYTHONUNBUFFERED=1
# At boot the VirtualBox shared folder can mount after this service starts.
# Iff the code isn't there yet check fails, and Restart= tries again 10s later.
ExecStartPre=/usr/bin/test -f $AGENT_SCRIPT
ExecStart=$PYTHON $AGENT_SCRIPT
Restart=always
RestartSec=10
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$UNIT_FILE"
echo "Wrote $UNIT_FILE"

if grep -q '^PROCESS_COLLECT=auditd' "$ENV_FILE"; then
    if command -v augenrules >/dev/null; then
        echo "-a always,exit -F arch=b64 -S execve -k edr_process_exec" > "$AUDIT_RULES"
        augenrules --load
        echo "Installed audit rule $AUDIT_RULES"
    else
        echo "WARNING: PROCESS_COLLECTOR=auditd but auditd isn't installed (sudo apt install auditd)." >&2
    fi
else
    rm -f "$AUDIT_RULES"
fi

systemctl daemon-reload
systemctl enable vigilon-edr
systemctl restart vigilon-edr
sleep 3
systemctl --no-pager --lines=5 status vigilon-edr || true
echo
echo "Installed. Live logs: sudo journalctl -u vigilon-edr -f"