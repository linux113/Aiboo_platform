#!/usr/bin/env bash
# AiBoO Linux Sentinel - start in the background (like run_agent.bat on Windows).
#
#   ./run_agent.sh              start (asks the settings the first time)
#   ./run_agent.sh --foreground show the log on screen instead (Ctrl+C stops it)
#
# Nothing needs root. The agent keeps running after you close the terminal
# (nohup), and it comes back by itself only if you use ./install_service.sh.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOREGROUND=0
[ "${1:-}" = "--foreground" ] && FOREGROUND=1

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "[ERROR] Python 3 is not installed.  Try:  sudo apt install python3"; exit 1; }

AGENT="$DIR/aiboo_linux_agent.py"
INI="$DIR/config.ini"
LOG="$DIR/agent.log"
PIDFILE="$DIR/agent.pid"

[ -f "$AGENT" ] || { echo "[ERROR] aiboo_linux_agent.py is not in $DIR"; exit 1; }

if [ ! -f "$INI" ]; then
  echo "First run: config.ini does not exist yet - let's set it up."
  bash "$DIR/configure.sh" --dir "$DIR" || exit 1
fi

url_of() { sed -n 's/^[[:space:]]*remote_url[[:space:]]*=[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$INI" | head -1; }
name_of() { sed -n 's/^[[:space:]]*endpoint_name[[:space:]]*=[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$INI" | head -1; }

running_pid() {                       # PID of our background agent, or nothing
  [ -f "$PIDFILE" ] || return 1
  local pid; pid="$(cat "$PIDFILE" 2>/dev/null)"
  [ -n "$pid" ] && [ -d "/proc/$pid" ] || return 1
  grep -qa "aiboo_linux_agent" "/proc/$pid/cmdline" 2>/dev/null || return 1
  echo "$pid"
}

if [ "$FOREGROUND" = "1" ]; then
  echo "Running in the foreground as '$(name_of)' -> $(url_of)"
  echo "(Ctrl+C stops it)"
  cd "$DIR" && exec "$PY" aiboo_linux_agent.py
fi

PID="$(running_pid || true)"
if [ -n "$PID" ]; then
  echo "[OK] already running (PID $PID) as '$(name_of)' -> $(url_of)"
  echo "     check it:  ./show_status.sh    stop it:  ./stop_agent.sh"
  exit 0
fi

if command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet aiboo-linux-agent 2>/dev/null; then
  echo "[OK] the agent is already running as the systemd user service 'aiboo-linux-agent'."
  echo "     Do not start a second copy. Use:  systemctl --user restart aiboo-linux-agent"
  echo "     Status:  ./show_status.sh"
  exit 0
fi

cd "$DIR"
nohup "$PY" aiboo_linux_agent.py >> "$LOG" 2>&1 &
PID=$!
echo "$PID" > "$PIDFILE"
sleep 3

if [ -d "/proc/$PID" ]; then
  echo "[OK] the AiBoO agent is RUNNING IN THE BACKGROUND (PID $PID)"
  echo "     server : $(url_of)"
  echo "     name   : $(name_of)"
  echo "     log    : $LOG"
  echo "     check  : ./show_status.sh"
  echo "     stop   : ./stop_agent.sh"
  echo
  echo "     It keeps running after you close this window, but NOT after a reboot."
  echo "     For always-on use:  ./install_service.sh"
  echo
  echo "--- last log lines -------------------------------------------"
  tail -8 "$LOG" 2>/dev/null | sed 's/^/   /'
else
  echo "[ERROR] the agent stopped immediately. Last log lines:"
  tail -20 "$LOG" 2>/dev/null | sed 's/^/   /'
  echo
  echo "Common causes:"
  echo "   HTTP 401  -> wrong api_key (run ./configure.sh again)"
  echo "   address   -> the server is not reachable (run ./configure.sh, it tests it)"
  echo "   python    -> python3 missing (sudo apt install python3)"
  exit 1
fi
