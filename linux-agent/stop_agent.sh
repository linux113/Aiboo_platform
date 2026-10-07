#!/usr/bin/env bash
# AiBoO Linux Sentinel - stop it (like stop_agent.bat).
#
#   ./stop_agent.sh                  stop the background copy and/or the service
#   ./stop_agent.sh --background     only the nohup copy from run_agent.sh
#   ./stop_agent.sh --service        only the systemd --user service
#
# The service is only STOPPED, not removed - use ./uninstall_service.sh for that.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHICH="all"
case "${1:-}" in
  --background) WHICH="background" ;;
  --service)    WHICH="service" ;;
  --all|"")     ;;
  *) echo "Usage: $0 [--background|--service|--all]"; exit 2 ;;
esac

PIDFILE="$DIR/agent.pid"
stopped=0

if [ "$WHICH" != "service" ]; then
  pid=""
  if [ -f "$PIDFILE" ]; then
    p="$(cat "$PIDFILE" 2>/dev/null)"
    if [ -n "$p" ] && [ -d "/proc/$p" ] && grep -qa "aiboo_linux_agent" "/proc/$p/cmdline" 2>/dev/null; then
      pid="$p"
    fi
  fi
  if [ -z "$pid" ]; then
    # no pid file: look for exactly our agent (never touch other people's processes)
    pid="$(pgrep -f "$DIR/aiboo_linux_agent.py" 2>/dev/null | head -1 || true)"
  fi
  if [ -n "$pid" ]; then
    echo "Stopping the background agent (PID $pid) ..."
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -d "/proc/$pid" ] || break
      sleep 1
    done
    if [ -d "/proc/$pid" ]; then
      echo "It did not stop by itself - killing it."
      kill -9 "$pid" 2>/dev/null || true
    fi
    echo "[OK] background agent stopped"
    stopped=1
  else
    [ "$WHICH" = "background" ] && echo "The background agent was not running."
  fi
  rm -f "$PIDFILE" 2>/dev/null || true
fi

if [ "$WHICH" != "background" ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl --user list-unit-files 2>/dev/null | grep -q '^aiboo-linux-agent'; then
    if systemctl --user is-active --quiet aiboo-linux-agent 2>/dev/null; then
      systemctl --user stop aiboo-linux-agent 2>/dev/null || true
      echo "[OK] systemd service stopped (it will start again after a reboot -"
      echo "     it is still enabled; ./uninstall_service.sh removes it completely)"
      stopped=1
    else
      [ "$WHICH" = "service" ] && echo "The systemd service is not running."
    fi
  else
    [ "$WHICH" = "service" ] && echo "The systemd service is not installed."
  fi
fi

if [ "$stopped" = "0" ]; then
  echo "Nothing was running - the dashboard will now show this server as OFFLINE."
else
  echo
  echo "Start again:  ./run_agent.sh       (or: systemctl --user start aiboo-linux-agent)"
fi
