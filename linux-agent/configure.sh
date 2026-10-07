#!/usr/bin/env bash
# AiBoO Linux Sentinel - first-time settings (the same job as configure.ps1 on Windows).
#
# Asks for the AiBoO server address and the API key, writes config.ini, then
# proves the connection works (GET /health and a real heartbeat POST).
#
#   ./configure.sh                          # asks the questions
#   ./configure.sh --url https://abcd.ngrok-free.app --key SECRET --yes
#   ./configure.sh --dir ~/aiboo-linux-agent
#
# Options: --url --key --name --importance --allow-response yes|no
#          --response-dry-run yes|no --dir --yes
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL=""; KEY=""; NAME=""; IMPORTANCE=""; ALLOW_RESPONSE=""; RESPONSE_DRY=""; ASSUME_YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --importance) IMPORTANCE="$2"; shift 2 ;;
    --allow-response) ALLOW_RESPONSE="$2"; shift 2 ;;
    --response-dry-run) RESPONSE_DRY="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "[ERROR] Python 3 is not installed.  Try:  sudo apt install python3"; exit 1; }

INI="$DIR/config.ini"
EXAMPLE="$DIR/config.ini.example"
AGENT="$DIR/aiboo_linux_agent.py"
[ -f "$AGENT" ] || { echo "[ERROR] aiboo_linux_agent.py is not in $DIR"; exit 1; }
[ -f "$EXAMPLE" ] || { echo "[ERROR] config.ini.example is not in $DIR"; exit 1; }

echo "============================================="
echo "  AiBoO Linux Sentinel - settings"
echo "============================================="
echo "Agent folder : $DIR"

# ---------------------------------------------------------------- what we have
get_key() {                       # read one value out of config.ini (or the example)
  local key="$1" file="${2:-$INI}"
  [ -f "$file" ] || return 0
  sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p" "$file" | head -1
}

CUR_URL="$(get_key remote_url)"
CUR_KEY="$(get_key api_key)"
CUR_NAME="$(get_key endpoint_name)"
CUR_IMP="$(get_key importance)"
CUR_ALLOW="$(get_key allow_response)"
CUR_DRY="$(get_key response_dry_run)"
HOSTNAME_NOW="$(hostname 2>/dev/null || echo linux-server)"

ask() {                           # ask prompt default  ->  echoes the answer
  local prompt="$1" def="${2:-}" answer=""
  if [ "$ASSUME_YES" = "1" ]; then echo "$def"; return; fi
  # ask() is used inside $( ), so the question must go to stderr: stdout is the answer
  if [ -n "$def" ]; then printf '%s [%s]: ' "$prompt" "$def" >&2; else printf '%s: ' "$prompt" >&2; fi
  read -r answer || true
  [ -n "$answer" ] && echo "$answer" || echo "$def"
}

echo
echo "The dashboard address is the AiBoO server (backend). Examples:"
echo "   same machine        :  http://127.0.0.1:4000"
echo "   cloud server        :  http://13.234.xx.xx:4000"
echo "   through ngrok       :  https://abcd-1234.ngrok-free.app"
echo "   https + real domain :  https://aiboo.example.com"
echo "(nothing after the address - no / and no /health)"
echo
[ -n "$URL" ] || URL="$(ask 'AiBoO server address' "$CUR_URL")"
URL="${URL%/}"; URL="${URL%/health}"

[ -n "$KEY" ] || KEY="$(ask 'API key (must equal AGENT_API_KEY on the server)' "$CUR_KEY")"
[ -n "$KEY" ] || KEY="dev-key-change-in-production"

[ -n "$NAME" ] || NAME="$(ask 'Name for this server on the dashboard' "${CUR_NAME:-$HOSTNAME_NOW}")"
[ -n "$NAME" ] || NAME="$HOSTNAME_NOW"

[ -n "$IMPORTANCE" ] || IMPORTANCE="$(ask 'Importance (low|normal|high|critical)' "${CUR_IMP:-high}")"
[ -n "$IMPORTANCE" ] || IMPORTANCE="high"

if [ -z "$ALLOW_RESPONSE" ]; then
  echo
  echo "May the dashboard CHANGE things on this server (block an IP, kill a process,"
  echo "quarantine a file)?  'no' = detection only, read-only.  'yes' needs root or"
  echo "the sudoers file (see README)."
  ALLOW_RESPONSE="$(ask 'allow_response (yes|no)' "${CUR_ALLOW:-no}")"
fi
case "$(echo "$ALLOW_RESPONSE" | tr 'A-Z' 'a-z')" in
  yes|y|true|1|on) ALLOW_RESPONSE="yes" ;;
  *) ALLOW_RESPONSE="no" ;;
esac

if [ -z "$RESPONSE_DRY" ]; then
  if [ "$ALLOW_RESPONSE" = "yes" ]; then
    echo
    echo "IMPORTANT: response_dry_run = yes means 'pretend': the dashboard shows a"
    echo "success but NOTHING is changed on the server.  Set 'no' for real action."
    RESPONSE_DRY="$(ask 'response_dry_run (yes = pretend, no = really act)' "${CUR_DRY:-yes}")"
  else
    RESPONSE_DRY="${CUR_DRY:-yes}"
  fi
fi
case "$(echo "$RESPONSE_DRY" | tr 'A-Z' 'a-z')" in
  no|n|false|0|off) RESPONSE_DRY="no" ;;
  *) RESPONSE_DRY="yes" ;;
esac

# ---------------------------------------------------------------- write config
case "$KEY" in
  YOUR-AGENT-KEY|YOUR-KEY|CHANGEME|changeme|API_KEY|'<key>')
    echo
    echo "ERROR: '$KEY' is a placeholder, not a real key."
    echo "   On the server that runs the backend:   grep AGENT_API_KEY backend/.env"
    echo "   Then run this script again and paste that value."
    exit 2 ;;
esac

[ -f "$INI" ] || cp -f "$EXAMPLE" "$INI"

"$PY" - "$INI" "$URL" "$KEY" "$NAME" "$IMPORTANCE" "$ALLOW_RESPONSE" "$RESPONSE_DRY" <<'PY'
import re, sys
ini, url, key, name, imp, allow, dry = sys.argv[1:8]
wanted = {
    "remote_url": url, "api_key": key, "endpoint_name": name,
    "importance": imp, "allow_response": allow, "response_dry_run": dry,
}
with open(ini, encoding="utf-8") as fh:
    lines = fh.read().splitlines()

def set_line(text, k, v):
    out, done = [], False
    for line in text:
        if not done and re.match(rf"^[ \t]*{re.escape(k)}[ \t]*=", line):
            out.append(f"{k} = {v}"); done = True
        else:
            out.append(line)
    if not done:                      # key was not there: add it near the top
        insert = 1 if out and out[0].strip().startswith("[") else 0
        out.insert(insert, f"{k} = {v}")
    return out

for k, v in wanted.items():
    lines = set_line(lines, k, v)
with open(ini, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"Settings written to {ini}")
PY

echo
echo "--- saved values ---------------------------------------------"
grep -nE "^(remote_url|api_key|endpoint_name|importance|allow_response|response_dry_run)[[:space:]]*=" "$INI" | sed 's/^/   /'
echo "   (the api key is stored in this file - keep it readable only by you: chmod 600 $INI)"

# ---------------------------------------------------------------- connection test
echo
echo "--- connection test ------------------------------------------"
if ! command -v curl >/dev/null 2>&1; then
  echo "(curl not installed - skipping. Test by hand: python3 -c \"import urllib.request;print(urllib.request.urlopen('$URL/health').read())\")"
  exit 0
fi

if curl -fsS --max-time 8 "$URL/health" >/dev/null 2>&1; then
  echo "[OK]   $URL/health answered - the dashboard is reachable from this server"
  HB="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        -X POST "$URL/api/agent/heartbeat" \
        -H "Content-Type: application/json" -H "x-api-key: $KEY" -H "x-endpoint-id: $NAME" \
        -d "{\"source\":\"$NAME\",\"platform\":\"linux\",\"status\":\"online\"}" 2>/dev/null)"
  case "$HB" in
    200|201) echo "[OK]   the server ACCEPTED the API key - '$NAME' is now on the Endpoints page" ;;
    401|403) echo "[FAIL] the server REJECTED the API key (HTTP $HB) - nothing will reach the dashboard."
             echo "       Copy the real AGENT_API_KEY from the server's backend/.env and run this again." ;;
    404)     echo "[WARN] heartbeat returned 404 - the address looks wrong (no /api at the end?)" ;;
    *)       echo "[WARN] heartbeat returned HTTP $HB - check the backend log on the server" ;;
  esac
else
  echo "[FAIL] cannot reach $URL/health"
  echo "       Check: 1) backend running on the server?  2) the address is right?"
  echo "              3) port 4000 open in the firewall / security group?"
  echo "              4) for ngrok: the tunnel is running and the address is current?"
fi
echo
echo "Next:  ./run_agent.sh      start it in the background"
echo "   or  ./install_service.sh   always on (starts with the machine)"
