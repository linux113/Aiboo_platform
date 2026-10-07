#!/usr/bin/env bash
# AiBoO Linux Sentinel - always on (like install_service.bat / nssm on Windows).
#
# Installs a systemd --user service: starts with the machine, restarts by
# itself after a crash, invisible in the background. No root needed.
#
#   ./install_service.sh              set up + start now
#   ./install_service.sh --no-start   only write the unit file
#   ./install_service.sh --linger     also survive reboots/logouts (may ask for sudo)
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_NAME="aiboo-linux-agent"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/$UNIT_NAME.service"
DO_START=1
DO_LINGER=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-start) DO_START=0; shift ;;
    --linger) DO_LINGER=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "[ERROR] Python 3 is not installed.  Try:  sudo apt install python3"; exit 1; }
AGENT="$DIR/aiboo_linux_agent.py"
INI="$DIR/config.ini"
[ -f "$AGENT" ] || { echo "[ERROR] aiboo_linux_agent.py is not in $DIR"; exit 1; }

if [ ! -f "$INI" ]; then
  echo "No config.ini yet - let's set the server address and key first."
  bash "$DIR/configure.sh" --dir "$DIR" || exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "[!] This machine has no systemd - the service route is not available."
  echo "    Start it by hand instead:   ./run_agent.sh"
  echo "    (or add it to /etc/rc.local / crontab: @reboot $PY $AGENT)"
  exit 1
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "[!] systemd --user is not available for this login (common in containers)."
  echo "    Try:  sudo loginctl enable-linger $USER   then log out and in again,"
  echo "    or simply use:  ./run_agent.sh"
  exit 1
fi

mkdir -p "$UNIT_DIR"
cat > "$UNIT" <<UNIT
[Unit]
Description=AiBoO Linux Sentinel (read-only log agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$PY $DIR/aiboo_linux_agent.py --config $DIR/config.ini
Restart=always
RestartSec=10
# polite: little CPU, little memory, no root, cannot write outside its folder
Nice=10
MemoryMax=256M
NoNewPrivileges=yes
StandardOutput=append:$DIR/agent.log
StandardError=append:$DIR/agent.log

[Install]
WantedBy=default.target
UNIT

echo "Service file written: $UNIT"
systemctl --user daemon-reload 2>/dev/null || true

if [ "$DO_START" = "1" ]; then
  systemctl --user enable --now "$UNIT_NAME.service" 2>/dev/null || true
  sleep 2
  if systemctl --user is-active --quiet "$UNIT_NAME" 2>/dev/null; then
    echo "[OK] the AiBoO agent is now a service and is RUNNING (starts with this machine)"
  else
    echo "[!] The service did not start. Ask it why:"
    echo "     systemctl --user status $UNIT_NAME"
    echo "     tail -20 $DIR/agent.log"
    exit 1
  fi
else
  echo "(not started - use: systemctl --user enable --now $UNIT_NAME)"
fi

echo
echo "status : ./show_status.sh                (or: systemctl --user status $UNIT_NAME)"
echo "log    : tail -f $DIR/agent.log          (or: journalctl --user -u $UNIT_NAME -f)"
echo "restart: systemctl --user restart $UNIT_NAME"
echo "stop   : ./stop_agent.sh"
echo "remove : ./uninstall_service.sh"

if [ "$DO_LINGER" = "1" ]; then
  echo
  echo "Making it survive a reboot / logout (needs sudo once) ..."
  sudo loginctl enable-linger "$USER" && echo "[OK] linger enabled"
else
  echo
  echo "NOTE: like every systemd --user service it stops when you fully log out / reboot"
  echo "      unless you allow lingering. Wake it up forever with:"
  echo "         sudo loginctl enable-linger $USER     (once, needs sudo)"
  echo "      or: ./install_service.sh --linger"
fi
