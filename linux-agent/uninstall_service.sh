#!/usr/bin/env bash
# AiBoO Linux Sentinel - remove the always-on service (like uninstall_service.bat).
#
#   ./uninstall_service.sh            stop + disable + remove the unit
#   ./uninstall_service.sh --purge    also delete config.ini, logs and state
#
# Your files, rules and settings stay in place unless you use --purge.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_NAME="aiboo-linux-agent"
UNIT="$HOME/.config/systemd/user/$UNIT_NAME.service"
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if command -v systemctl >/dev/null 2>&1; then
  if [ -f "$UNIT" ]; then
    systemctl --user stop "$UNIT_NAME" 2>/dev/null || true
    systemctl --user disable "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT"
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user reset-failed "$UNIT_NAME" 2>/dev/null || true
    echo "[OK] service removed: $UNIT_NAME"
  else
    echo "The service was not installed ($UNIT not found)."
  fi
else
  echo "(no systemctl on this machine - nothing to remove)"
fi

# a background copy from run_agent.sh, if there is one
bash "$DIR/stop_agent.sh" --background 2>/dev/null || true

if [ "$PURGE" = "1" ]; then
  echo
  echo "Deleting the agent's own data (config, logs, state) ..."
  rm -f "$DIR/config.ini" "$DIR/agent.log" "$DIR/agent.pid" \
        "$DIR/linux-agent-state.json" "$DIR/linux-agent-queue.jsonl" "$DIR/actions.jsonl"
  rm -rf "$DIR/quarantine" "$DIR/state"
  echo "[OK] removed config.ini, logs, saved state, queue and quarantine"
  echo "     (the python files are still here - delete the folder to remove them)"
fi
echo
echo "The dashboard will now show this server as OFFLINE."
echo "To put it back:  ./configure.sh   then   ./install_service.sh"
