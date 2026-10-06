#!/usr/bin/env bash
# AiBoO Linux Sentinel - attack demo
#
# Runs a short, REAL attack sequence against this server and shows what the
# dashboard raises. Everything is non-destructive and cleans up after itself.
#
#   Phase 1  replay of an attack log   (safe, no system changes at all)
#   Phase 2  real events on this box   (web shell file, set-uid in /tmp, a
#                                       reverse-shell process for ~30 seconds,
#                                       a log-wipe command)
#
# Usage:
#   sudo bash tests/attack_demo.sh                       # full demo
#   sudo bash tests/attack_demo.sh --config ~/aiboo-linux-agent/config.ini
#   bash tests/attack_demo.sh --phase1                   # no root needed
#
# What the dashboard should show afterwards is printed at the end.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT="$DIR/../aiboo_linux_agent.py"
PY="$(command -v python3 || command -v python)"
CFG="${AIBOO_CONFIG:-$DIR/../config.ini}"
PHASE1_ONLY=0
WORK="$(mktemp -d /tmp/aiboo-demo-XXXXXX)"
ATTACKER="45.95.147.3"        # documentation/public example IP used by AiBoO tests
ROOTME="$WORK/rootme-suid"

while [ $# -gt 0 ]; do
  case "$1" in
    --phase1) PHASE1_ONLY=1 ;;
    --config) shift; CFG="${1:-$CFG}" ;;
    --config=*) CFG="${1#--config=}" ;;
  esac
  shift
done

line() { printf '\n\033[1m=== %s\033[0m\n' "$1"; }
note() { printf '    %s\n' "$1"; }

[ -f "$AGENT" ] || { echo "aiboo_linux_agent.py not found next to this script"; exit 2; }
if [ ! -f "$CFG" ]; then
  echo "No config.ini at $CFG"
  echo "Point me at the installed one, e.g.:"
  echo "    sudo bash tests/attack_demo.sh --config ~/aiboo-linux-agent/config.ini"
  exit 2
fi
echo "AiBoO Linux Sentinel - attack demo"
echo "server : $(hostname)   user: $(id -un)"
echo "agent  : $AGENT"
echo "config : $CFG"
echo "attacker IP used in phase 1: $ATTACKER (safe example address, never contacted)"

run_agent() { "$PY" "$AGENT" --config "$CFG" "$@"; }

# ---------------------------------------------------------------------------
line "PHASE 1 - replay an attack log (nothing on this server is touched)"

# timestamps must be 'now' so the replay looks like a live attack
now_ts() { date -d "$1" '+%b %d %H:%M:%S'; }
AUTH="$WORK/auth.log"
{
  printf '%s web sshd[1101]: Invalid user admin from %s port 40001 ssh2\n' "$(now_ts '-6 min')" "$ATTACKER"
  printf '%s web sshd[1102]: Failed password for invalid user admin from %s port 40002 ssh2\n' "$(now_ts '-5 min')" "$ATTACKER"
  printf '%s web sshd[1103]: Failed password for root from %s port 40003 ssh2\n' "$(now_ts '-5 min')" "$ATTACKER"
  printf '%s web sshd[1104]: Failed password for root from %s port 40004 ssh2\n' "$(now_ts '-4 min')" "$ATTACKER"
  printf '%s web sshd[1105]: Failed password for root from %s port 40005 ssh2\n' "$(now_ts '-4 min')" "$ATTACKER"
  printf '%s web sshd[1106]: Failed password for root from %s port 40006 ssh2\n' "$(now_ts '-3 min')" "$ATTACKER"
  printf '%s web sshd[1107]: Accepted password for deploy from %s port 40010 ssh2\n' "$(now_ts '-2 min')" "$ATTACKER"
  printf '%s web sudo: bob : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /var/log/auth.log\n' "$(now_ts '-1 min')"
} > "$AUTH"

ACCESS="$WORK/access.log"
{
  printf '%s - - [%s +0000] "GET /api/login?u=admin%%27%%20OR%%20%%271%%27%%3D%%271 HTTP/1.1" 403 512 "-" "sqlmap/1.7"\n' \
     "$ATTACKER" "$(date -d '-8 min' '+%d/%b/%Y:%H:%M:%S')"
  printf '%s - - [%s +0000] "GET /.env HTTP/1.1" 200 88 "-" "curl/8.5.0"\n' \
     "$ATTACKER" "$(date -d '-7 min' '+%d/%b/%Y:%H:%M:%S')"
} > "$ACCESS"

for f in "$AUTH" "$ACCESS"; do
  note "local proof (--dry-run, nothing sent):"
  run_agent --replay "$f" --dry-run 2>&1 \
    | grep -oE "\[(dry-run)\] +(CRITICAL|HIGH|MEDIUM|LOW) +[a-z_]+ +.{0,58}" \
    | sed 's/\[dry-run\] //' | sort -u | head -8
  note "sending the same events to the dashboard:"
  run_agent --replay "$f" 2>&1 | grep -viE "warning|warn" | tail -2
done

if [ "$PHASE1_ONLY" = "1" ]; then
  line "PHASE 1 DONE (phase 2 skipped: --phase1)"
  exit 0
fi

# ---------------------------------------------------------------------------
line "PHASE 2 - real events on this server (all removed again at the end)"
CLEANUP=()
cleanup() {
  for item in "${CLEANUP[@]:-}"; do
    case "$item" in
      pid:*)   kill -9 "${item#pid:}" 2>/dev/null ;;
      file:*)  rm -f "${item#file:}" 2>/dev/null ;;
    esac
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# 2a. web shell dropped in a watched folder --------------------------------
WEBDIR=""
for cand in /var/www /var/www/html /srv /opt; do
  if [ -d "$cand" ] && [ -w "$cand" ]; then WEBDIR="$cand"; break; fi
  if [ -d "$cand" ] && [ "$(id -u)" = "0" ]; then WEBDIR="$cand"; break; fi
done
if [ -z "$WEBDIR" ] && [ "$(id -u)" = "0" ]; then
  mkdir -p /var/www 2>/dev/null && WEBDIR=/var/www
  note "created the standard web root /var/www for this demo"
fi
if [ -n "$WEBDIR" ]; then
  SHELLFILE="$WEBDIR/aiboo-demo-shell.php"
  printf '<?php /* AiBoO demo - not a working shell */ system($_GET["c"]); ?>\n' > "$SHELLFILE"
  CLEANUP+=("file:$SHELLFILE")
  note "web shell written: $SHELLFILE"
else
  note "no writable web folder found - skipping the web-shell step"
fi

# 2b. set-uid binary in /tmp (the attacker favourite) ----------------------
cp /bin/true "$ROOTME" 2>/dev/null && chmod 4755 "$ROOTME"
CLEANUP+=("file:$ROOTME")
note "set-uid binary planted: $ROOTME (mode $(stat -c '%a' "$ROOTME" 2>/dev/null))"

# 2c. a real reverse-shell-looking process for ~30 seconds ------------------
"$PY" -c "import socket,time; s=socket.socket(); time.sleep(30)" 2>/dev/null &
SHELL_PID=$!
CLEANUP+=("pid:$SHELL_PID")
note "reverse-shell process started: PID $SHELL_PID (python3 -c 'import socket ...')"

# 2d. real log-wipe command (on a DEMO log, never the system one) -----------
mkdir -p "$WORK/logs"
printf 'demo content\n' > "$WORK/logs/auth.log"
if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then
  TRUNC="sudo truncate -s 0 $WORK/logs/auth.log"
  $TRUNC >/dev/null 2>&1
  note "ran: $TRUNC  (the real sudo line lands in /var/log/auth.log)"
else
  note "not root: skipping the log-wipe step (run the demo with sudo to include it)"
fi

# 2e. let the agent read everything once -----------------------------------
note "asking the agent to read new lines / scan processes now"
run_agent --once 2>&1 | tail -12

# ---------------------------------------------------------------------------
line "WHAT TO LOOK FOR IN THE DASHBOARD"
cat <<'EOF'
  Phase 1 (attack log replay)
    HIGH      brute force              - 5 failed SSH logons from 45.95.147.3
    CRITICAL  login_after_brute_force  - 'deploy' logged in right after them  -> BLOCK
    CRITICAL  log_cleared              - truncate -s 0 /var/log/auth.log      -> BLOCK
    HIGH      sql_injection / sensitive_file_hit -.env download from the web log -> BLOCK

  Phase 2 (real events on this server)
    HIGH      dropped_file     - aiboo-demo-shell.php written in the web root
    HIGH      suid_binary      - a set-uid binary planted in /tmp (not a system folder)
    CRITICAL  reverse_shell    - a python process holding a C2 socket (/proc scan)
    CRITICAL  log_cleared      - the truncate command you just ran with sudo

  If allow_response = yes, the Block IP / Terminate / Quarantine buttons can act
  on these. With the default allow_response = no the agent answers "READ-ONLY mode".
EOF

line "CLEANUP"
echo "  The demo removes its own files and stops its own process when it exits:"
echo "    - $ROOTME (set-uid binary)"
echo "    - any aiboo-demo-shell.php it created"
echo "    - the reverse-shell process (PID ${SHELL_PID:-none})"
echo "  The alerts stay in the dashboard on purpose - that is the evidence.

  Running the demo a second time on the same server shows nothing new: the agent
  already sent those events (that is the dedup working). To see it again:
      python3 aiboo_linux_agent.py --config CONFIG --reset-state
  then run this script once more."
