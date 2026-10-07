#!/usr/bin/env bash
# Start Vigilon's containers, wait until the GUI answers, then open it as a desktop app window.
# Usage: ./scripts/vigilon.sh            start and open
#        ./scripts/vigilon.sh --build    rebuild images first (after you change code)
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUI_URL="${VIGILON_GUI_URL:-http://localhost:8080}"
BUILD_FLAG=""
[ "${1:-}" = "--build" ] && BUILD_FLAG="--build"

# When started from the app menu there is no terminal, so also write to a log file
LOG_FILE="$PROJECT_DIR/logs/vigilon-launcher.log"
mkdir -p "$PROJECT_DIR/logs"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[vigilon] $(date '+%F %T') starting"

notify() {
    # Desktop pop-up if available, otherwise just the log
    command -v notify-send >/dev/null && notify-send -i "$PROJECT_DIR/gui/static/img/icon-192.png" "Vigilon" "$1" || true
}

cd "$PROJECT_DIR"
if ! docker compose up -d $BUILD_FLAG; then
    notify "Couldn't start the containers. See logs/vigilon-launcher.log"
    exit 1
fi

echo "[vigilon] waiting for the GUI at $GUI_URL"
for attempt in $(seq 1 90); do
    if curl -fsS "$GUI_URL/healthz" >/dev/null 2>&1; then
        break
    fi
    if [ "$attempt" -eq 90 ]; then
        notify "The GUI didn't start within 3 minutes. Run: docker compose logs gui"
        exit 1
    fi
    sleep 2
done

echo "[vigilon] GUI is up, opening the app window"
if command -v chromium >/dev/null; then
    # --user-data-dir = its own profile, so it opens as a separate app, not a tab in your browser
    PROFILE="$HOME/.config/vigilon-app"
    APP_ID="cpdpbfelifklonephgpieimdpcecgoen"   # Chromium's ID for the installed Vigilon app (manifest "id": "/")
    if [ -d "$PROFILE/Default/Web Applications/Manifest Resources/$APP_ID" ]; then
        # Installed app: no grey title bar (window controls overlay) and the owl in the taskbar
        nohup chromium --app-id="$APP_ID" --user-data-dir="$PROFILE" >/dev/null 2>&1 &
    else
        # Not installed yet: plain app window (see Project Implementation/Notes/VIGILON_APP_WINDOW_NOTES.md to install)
        nohup chromium --app="$GUI_URL" --user-data-dir="$PROFILE" --window-size=1280,860 >/dev/null 2>&1 &
    fi
else
    xdg-open "$GUI_URL" >/dev/null 2>&1 &
fi