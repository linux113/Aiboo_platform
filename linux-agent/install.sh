#!/usr/bin/env bash
# AiBoO Linux Sentinel - installer (read-only log agent).
#
# Nothing here needs root: it installs for the CURRENT USER only.
#   - checks Python 3.8+
#   - copies the agent to ~/aiboo-linux-agent
#   - asks for the server address (or takes it from the command line)
#   - runs a dry-run self test
#   - installs a systemd --user service, OR prints the nohup command
#
# Usage:
#   ./install.sh                                   # interactive
#   ./install.sh --url http://1.2.3.4:4000 --key SECRET --name auroraa-prod-ubuntu
#   ./install.sh --url ... --no-service            # just copy files + test
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST_DIR="${AIBOO_DIR:-$HOME/aiboo-linux-agent}"
URL=""
KEY=""
NAME="$(hostname)"
IMPORTANCE="high"
WANT_SERVICE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --importance) IMPORTANCE="$2"; shift 2 ;;
    --dir) DEST_DIR="$2"; shift 2 ;;
    --no-service) WANT_SERVICE=0; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

echo "============================================="
echo "  AiBoO Linux Sentinel - install"
echo "============================================="

# ---- 1. python -------------------------------------------------------------
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
[ -n "$PY" ] || { echo "[ERROR] Python 3 is not installed (apt install python3)"; exit 1; }
"$PY" - <<'PYCHECK'
import sys
if sys.version_info < (3, 8):
    print("[ERROR] Python 3.8 or newer is needed, found", sys.version.split()[0]); sys.exit(1)
print("Python", sys.version.split()[0], "OK")
PYCHECK

# ---- 2. copy ---------------------------------------------------------------
mkdir -p "$DEST_DIR"
cp -f "$SRC_DIR/aiboo_linux_agent.py" "$DEST_DIR/"
[ -f "$SRC_DIR/aiboo_linux_response.py" ] && cp -f "$SRC_DIR/aiboo_linux_response.py" "$DEST_DIR/"
cp -f "$SRC_DIR/config.ini.example" "$DEST_DIR/"
mkdir -p "$DEST_DIR/sudoers" "$DEST_DIR/audit-rules"
[ -f "$SRC_DIR/sudoers/aiboo-linux-agent.sudoers" ] && cp -f "$SRC_DIR/sudoers/aiboo-linux-agent.sudoers" "$DEST_DIR/sudoers/"
[ -f "$SRC_DIR/audit-rules/aiboo.rules" ] && cp -f "$SRC_DIR/audit-rules/aiboo.rules" "$DEST_DIR/audit-rules/"
[ -f "$SRC_DIR/rules.json" ] && cp -f "$SRC_DIR/rules.json" "$DEST_DIR/"
[ -f "$SRC_DIR/blocklist.txt" ] && [ ! -f "$DEST_DIR/blocklist.txt" ] && cp -f "$SRC_DIR/blocklist.txt" "$DEST_DIR/"
# the everyday helper scripts (same idea as the Windows .bat files)
for helper in configure.sh run_agent.sh show_status.sh stop_agent.sh install_service.sh uninstall_service.sh; do
  if [ -f "$SRC_DIR/$helper" ]; then
    cp -f "$SRC_DIR/$helper" "$DEST_DIR/"
    chmod +x "$DEST_DIR/$helper"
  fi
done
echo "Files copied to $DEST_DIR"

# ---- 3. settings -----------------------------------------------------------
if [ -z "$URL" ]; then
  printf 'AiBoO server address (e.g. http://13.234.x.x:4000): '
  read -r URL
fi
URL="${URL%/}"; URL="${URL%/health}"
if [ -z "$KEY" ]; then
  printf 'API key [press ENTER to keep dev-key-change-in-production]: '
  read -r KEY
fi
[ -n "$KEY" ] || KEY="dev-key-change-in-production"
case "$KEY" in
  YOUR-AGENT-KEY|YOUR-KEY|CHANGEME|changeme|API_KEY|"<key>"|"")
    echo
    echo "ERROR: '$KEY' is a placeholder, not a real key."
    echo "Copy the real value of AGENT_API_KEY from backend/.env on the machine"
    echo "running the AiBoO backend, or from an agent that already works:"
    echo "    grep -E '^(remote_url|api_key)' ~/aiboo/linux-agent/config.ini"
    echo "The agent will get HTTP 401 until the key is right, so nothing is installed."
    exit 2
    ;;
esac

INI="$DEST_DIR/config.ini"
sed -e "s|^remote_url =.*|remote_url = $URL|" \
    -e "s|^api_key =.*|api_key = $KEY|" \
    -e "s|^endpoint_name =.*|endpoint_name = $NAME|" \
    -e "s|^importance =.*|importance = $IMPORTANCE|" \
    "$DEST_DIR/config.ini.example" > "$INI"
echo "Settings written to $INI"

# ---- 4. self test (no server needed) ---------------------------------------
echo
echo "--- built-in parser test -------------------------------------"
"$PY" "$DEST_DIR/aiboo_linux_agent.py" --selftest

# ---- 5. live dry-run (reads this machine's logs, sends NOTHING) ------------
echo
echo "--- dry run on THIS machine's real logs (nothing is sent) -----"
( cd "$DEST_DIR" && "$PY" aiboo_linux_agent.py --once --dry-run ) || true

# ---- 5b. what can this agent change on this server? ------------------------
echo
echo "--- local response (dashboard actions) -----------------------"
"$PY" "$DEST_DIR/aiboo_linux_agent.py" --capabilities || true
echo "(allow_response is 'no' by default: detection only. See the README section"
echo " 'Let the dashboard act on this server' to turn it on safely.)"

# ---- 6. check the server is reachable --------------------------------------
echo
echo "--- server check ---------------------------------------------"
if command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 8 "$URL/health" >/dev/null 2>&1; then
    echo "[OK] $URL/health answered"
    HB=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
         -X POST "$URL/api/agent/heartbeat" \
         -H "Content-Type: application/json" -H "x-api-key: $KEY" -H "x-endpoint-id: $NAME" \
         -d "{\"source\":\"$NAME\",\"platform\":\"linux\",\"status\":\"online\"}" 2>/dev/null)
    case "$HB" in
      200|201)
        echo "[OK] the server ACCEPTED the API key (heartbeat sent as '$NAME')"
        ;;
      401|403)
        echo "[!] The server REJECTED the API key (HTTP $HB)."
        echo "    Nothing will reach the dashboard until this is fixed."
        echo "    Get the right key, then run:"
        echo "      grep -E '^(remote_url|api_key)' ~/aiboo/linux-agent/config.ini"
        echo "      nano $INI      # set api_key = <that value>"
        echo "      systemctl --user restart aiboo-linux-agent"
        ;;
      *)
        echo "[?] heartbeat returned HTTP $HB - check the backend log"
        ;;
    esac
  else
    echo "[!] Cannot reach $URL/health - check the address, the security group"
    echo "    (port 4000 open?) and that the AiBoO backend is running."
  fi
else
  echo "(curl not installed - skipping the server check)"
fi

# ---- 7. service ------------------------------------------------------------
if [ "$WANT_SERVICE" = "1" ] && command -v systemctl >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/aiboo-linux-agent.service" <<UNIT
[Unit]
Description=AiBoO Linux Sentinel (read-only log agent)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$DEST_DIR
ExecStart=/usr/bin/env $PY $DEST_DIR/aiboo_linux_agent.py
Restart=always
RestartSec=10
# keep it polite: low CPU and memory, no root
Nice=10
MemoryMax=256M
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$DEST_DIR

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload || true
  if systemctl --user enable --now aiboo-linux-agent.service 2>/dev/null; then
    echo "[OK] service installed and started: aiboo-linux-agent.service"
    echo "     status : systemctl --user status aiboo-linux-agent"
    echo "     log    : journalctl --user -u aiboo-linux-agent -f"
    echo "     survive logout/reboot:  sudo loginctl enable-linger $USER"
  else
    echo "[!] Could not start the user service. Run it by hand instead:"
    echo "     cd $DEST_DIR && nohup $PY aiboo_linux_agent.py >> agent.log 2>&1 &"
  fi
else
  echo "Start it by hand:"
  echo "  cd $DEST_DIR && nohup $PY aiboo_linux_agent.py >> agent.log 2>&1 &"
fi

echo
if [ -f "$DEST_DIR/audit-rules/aiboo.rules" ]; then
  if [ -f /var/log/audit/audit.log ]; then
    echo "auditd is installed. For kernel-level process visibility (reverse shells,"
    echo "ptrace), ask the server admin to run:"
    echo "    sudo cp $DEST_DIR/audit-rules/aiboo.rules /etc/audit/rules.d/ && sudo augenrules --load"
  else
    echo "Tip: with auditd (sudo apt install auditd) the agent also sees the kernel's"
    echo "own process record. Rules are in $DEST_DIR/audit-rules/aiboo.rules"
  fi
fi
echo
echo "Everyday commands (in $DEST_DIR):"
echo "    ./show_status.sh        is it running / connected?"
echo "    ./run_agent.sh          start it in the background"
echo "    ./stop_agent.sh         stop it"
echo "    ./configure.sh          change the server address or API key"
echo "    ./install_service.sh    always on (starts with the machine)"
echo
echo "Done. On the dashboard open Endpoints - '$NAME' should appear as Online (Linux)."
