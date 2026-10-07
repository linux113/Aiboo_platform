#!/usr/bin/env bash
# AiBoO Linux Sentinel - is it running and connected? (like show_status.bat)
#
#   ./show_status.sh            full status
#   ./show_status.sh --brief    one line only (good for scripts / cron)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRIEF=0
[ "${1:-}" = "--brief" ] && BRIEF=1

INI="$DIR/config.ini"
LOG="$DIR/agent.log"
PIDFILE="$DIR/agent.pid"

val() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p" "$INI" 2>/dev/null | head -1; }

URL="$(val remote_url)"
NAME="$(val endpoint_name)"
KEY="$(val api_key)"
ALLOW="$(val allow_response)"
DRY="$(val response_dry_run)"

SERVICE_STATE="none"
if command -v systemctl >/dev/null 2>&1; then
  if systemctl --user list-unit-files 2>/dev/null | grep -q '^aiboo-linux-agent'; then
    SERVICE_STATE="$(systemctl --user is-active aiboo-linux-agent 2>/dev/null || echo inactive)"
  fi
fi

PID=""
if [ -f "$PIDFILE" ]; then
  p="$(cat "$PIDFILE" 2>/dev/null)"
  if [ -n "$p" ] && [ -d "/proc/$p" ] && grep -qa "aiboo_linux_agent" "/proc/$p/cmdline" 2>/dev/null; then
    PID="$p"
  fi
fi

if [ "$BRIEF" = "1" ]; then
  if [ -n "$PID" ]; then echo "running (pid $PID) as ${NAME:-?} -> ${URL:-?}"
  elif [ "$SERVICE_STATE" = "active" ]; then echo "running (systemd service) as ${NAME:-?} -> ${URL:-?}"
  else echo "not running"; [ "$SERVICE_STATE" != "none" ] && echo "service state: $SERVICE_STATE"; fi
  exit 0
fi

echo "============================================="
echo "  AiBoO Linux Sentinel - status"
echo "============================================="
echo "Agent folder : $DIR"
echo "Server       : ${URL:-(not set - run ./configure.sh)}"
echo "Name on the dashboard: ${NAME:-?}"

if [ -n "$PID" ]; then
  UPTIME="$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')"
  echo "Background copy: RUNNING (PID $PID, up $UPTIME)"
elif [ "$SERVICE_STATE" = "active" ]; then
  echo "Background copy: none (it runs as the systemd --user service)"
else
  echo "Background copy: not running"
fi
case "$SERVICE_STATE" in
  active)  echo "Systemd service: active (always on, starts with the machine)" ;;
  failed)  echo "Systemd service: FAILED - see: journalctl --user -u aiboo-linux-agent -n 40" ;;
  inactive) echo "Systemd service: installed but stopped - start: systemctl --user start aiboo-linux-agent" ;;
  *)       echo "Systemd service: not installed (./install_service.sh makes it always-on)" ;;
esac

if [ -z "$PID" ] && [ "$SERVICE_STATE" != "active" ]; then
  echo
  echo "Nothing is running, so the dashboard will show this server as offline."
  echo "   start once :  ./run_agent.sh"
  echo "   always on  :  ./install_service.sh"
fi

# ------------------------------------------------------------------ connection
echo
echo "--- server reachable? ----------------------------------------"
if command -v curl >/dev/null 2>&1 && [ -n "$URL" ]; then
  if curl -fsS --max-time 6 "$URL/health" >/dev/null 2>&1; then
    echo "[OK] $URL/health answered"
  else
    echo "[FAIL] cannot reach $URL/health (backend down, wrong address, or firewall)"
  fi
fi

# -------------------------------------------------------------------- last log
echo
echo "--- last 15 log lines ($LOG) ---------------------------------"
if [ -f "$LOG" ]; then
  tail -15 "$LOG" | sed 's/^/   /'
  echo
  LAST_SEND="$(grep -c 'finding(s)' "$LOG" 2>/dev/null | head -1)"
  [ -n "${LAST_SEND:-}" ] || LAST_SEND=0
  echo "   (log lines that reported findings so far: $LAST_SEND)"
else
  echo "   (no log file yet - it is written by ./run_agent.sh)"
fi

# --------------------------------------------------------------- what it may do
PY="$(command -v python3 || command -v python || true)"
if [ -n "$PY" ] && [ -f "$DIR/aiboo_linux_agent.py" ]; then
  echo
  echo "--- what this agent is allowed to change ---------------------"
  "$PY" "$DIR/aiboo_linux_agent.py" --config "$INI" --capabilities 2>/dev/null \
    | sed -n '1,12p' | sed 's/^/   /' || true
fi

echo
echo "Settings: ${ALLOW:-no} (allow_response) / ${DRY:-yes} (response_dry_run)"
if [ "${ALLOW:-no}" = "yes" ] && [ "${DRY:-yes}" = "yes" ]; then
  echo "NOTE: response_dry_run = yes -> the dashboard will show \"(dry-run) would ...\","
  echo "      and nothing is really changed on this server. Set it to no for real action."
fi
echo
echo "Also useful:  ./configure.sh (change server/key)   ./stop_agent.sh   tail -f $LOG"
