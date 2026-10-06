#!/usr/bin/env bash
# AiBoO Linux Sentinel - "prove it is real" script.
#
# Runs the response engine + EDR collectors against the REAL system it is started
# on and prints a PASS/FAIL list. Nothing here is simulated: processes are really
# killed, files are really moved, a real decoy port is opened and hit, and (if you
# allow it) a real firewall rule is added and removed again.
#
# Usage:
#   sudo bash prove_real.sh                 # full test (firewall + account need root)
#   bash prove_real.sh                      # tests that need no root only
#   bash prove_real.sh --keep-user          # do not delete the test account at the end
#   bash prove_real.sh --no-firewall        # skip the iptables/ufw part
#
# Everything it creates is removed again (test user, firewall rule, temp dirs),
# except files under the agent folder that are part of normal operation.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT="$DIR/../aiboo_linux_agent.py"
PY="$(command -v python3 || command -v python)"
KEEP_USER=0
NO_FIREWALL=0
for a in "$@"; do
  case "$a" in
    --keep-user) KEEP_USER=1 ;;
    --no-firewall) NO_FIREWALL=1 ;;
  esac
done

TEST_USER="aibootest$RANDOM"
TEST_IP="203.0.113.66"          # TEST-NET-3: reserved for documentation, never a real host
WORK="$(mktemp -d /tmp/aiboo-prove-XXXXXX)"
PASS=0; FAIL=0

line() { printf '\n=== %s\n' "$1"; }
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; }

echo "AiBoO Linux Sentinel - real-behaviour proof"
echo "host   : $(hostname)   user: $(id -un) ($(id -u))"
echo "system : $( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -sr )"
echo "python : $($PY --version 2>&1)"
echo "agent  : $AGENT"
[ -f "$AGENT" ] || { echo "aiboo_linux_agent.py not found next to this script"; exit 2; }

# --- a config that allows actions and does NOT dry-run ----------------------
CFG="$WORK/config.ini"
cat > "$CFG" <<EOF
[AIBOO]
remote_url = http://127.0.0.1:4000
api_key = not-used-in-this-test
endpoint_name = prove-real-$(hostname | cut -c1-12)
importance = normal
allow_response = yes
response_dry_run = no
quarantine_dir = $WORK/quarantine
watch_dirs = $WORK/watch
auth_log = /var/log/auth.log
extra_logs =
verify_tls = no
EOF
mkdir -p "$WORK/watch"

run_action() {  # action, target
  "$PY" "$AGENT" --config "$CFG" --run-action "$1" --target "$2" 2>&1
}

# ---------------------------------------------------------------------------
line "1. kill a real process (terminate_process)"
"$PY" -c 'import subprocess,time,sys; p=subprocess.Popen(["sleep","600"]); open("/tmp/aiboo-prove-pid","w").write(str(p.pid)); time.sleep(30)' &
SLEEPER_WRAPPER=$!
for _ in $(seq 1 20); do [ -s /tmp/aiboo-prove-pid ] && break; sleep 0.2; done
PID="$(cat /tmp/aiboo-prove-pid 2>/dev/null || true)"
if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
  OUT="$(run_action terminate_process "$PID")"
  sleep 0.5
  PSTATE="$(ps -o stat= -p "$PID" 2>/dev/null | tr -d ' ')"
  if [ -z "$PSTATE" ] || [ "${PSTATE#Z}" != "$PSTATE" ]; then
    ok "process $PID really killed (state '${PSTATE:-gone}')"
  else
    bad "process $PID is still alive (state $PSTATE)"
  fi
else
  bad "could not spawn a process to kill"
fi
kill "$SLEEPER_WRAPPER" 2>/dev/null; rm -f /tmp/aiboo-prove-pid

line "2. quarantine a real file (quarantine_file / restore_file)"
echo '<?php system($_GET["c"]); ?>' > "$WORK/watch/evil.php"
OUT="$(run_action quarantine_file "$WORK/watch/evil.php" | tr -d '\n')"
if [ -f "$WORK/watch/evil.php" ]; then bad "file was not moved away"; else ok "file moved out of the web root"; fi
Q="$(find "$WORK/quarantine" -name '*evil.php' 2>/dev/null | head -1)"
if [ -n "${Q:-}" ]; then
  PERM="$(stat -c '%a' "$Q" 2>/dev/null)"
  ok "quarantine copy kept: $Q (mode $PERM)"
else
  bad "no quarantined copy found"
fi
OUT2="$(run_action restore_file "$WORK/watch/evil.php" | tr -d '\n')"
[ -f "$WORK/watch/evil.php" ] && ok "restore_file put it back" || bad "restore_file did not restore the file"

line "3. decoy port (pseudo_lock) - connect to it like an intruder"
OUT="$("$PY" - "$AGENT" "$CFG" <<'PYEOF'
import importlib.util, socket, sys, time
from pathlib import Path
agent_path, cfg_path = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("la", agent_path)
m = importlib.util.module_from_spec(spec); sys.modules["la"] = m; spec.loader.exec_module(m)
st = m.load_settings(Path(cfg_path))
spec2 = importlib.util.spec_from_file_location("lr", Path(agent_path).with_name("aiboo_linux_response.py"))
r = importlib.util.module_from_spec(spec2); sys.modules["lr"] = r; spec2.loader.exec_module(r)
eng = r.ResponseEngine(st, lambda msg, level="INFO": None, Path(cfg_path).parent)
out = eng.execute("pseudo_lock", "prove-it")
port = out["metadata"]["decoy_port"]
s = socket.create_connection(("127.0.0.1", port), timeout=5)
banner = s.recv(64); s.sendall(b"root:toor\n"); s.close(); time.sleep(0.4)
hits = [e for e in eng.drain_events() if e["kind"] == "decoy_hit"]
safe = banner[:24].decode(errors="replace").replace("\r", " ").replace("\n", " ").strip()
payload = (hits[0]['payload'] if hits else "").replace("\r", " ").replace("\n", " ").strip()
print(f"{port}|{safe}|{len(hits)}|{payload}")
eng.execute("restore_pseudo_lock", out["metadata"]["lock_id"])
PYEOF
)"
IFS='|' read -r PORT BANNER HITS PAYLOAD <<< "$OUT"
if [ "${HITS:-0}" -ge 1 ] 2>/dev/null; then
  ok "decoy on port $PORT answered '$BANNER' and recorded payload '$PAYLOAD'"
else
  bad "decoy recorded no hit (got: $OUT)"
fi

line "4. reverse-shell detection on this machine (/proc scan)"
OUT="$("$PY" - "$AGENT" <<'PYEOF'
import importlib.util, subprocess, sys, tempfile, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("la2", sys.argv[1])
m = importlib.util.module_from_spec(spec); sys.modules["la2"] = m; spec.loader.exec_module(m)
c2 = subprocess.Popen([sys.executable, "-c", "import socket,time; s=socket.socket(); time.sleep(30)"])
time.sleep(0.4)
st = m.Settings(dry_run=True, watch_dirs="")
state = m.AgentState(Path(tempfile.mkdtemp()) / "s.json"); state.counters.now = time.time()
found = [f for f in m.detect_suspicious_processes(st, state) if f.pattern == "reverse_shell"]
print(f"{len(found)}|{found[0].summary[:110] if found else ''}|{any(str(c2.pid) in f.summary for f in found)}")
c2.kill()
PYEOF
)"
IFS='|' read -r N SUMMARY HIT <<< "$OUT"
if [ "${HIT:-False}" = "True" ]; then ok "found the fake C2: $SUMMARY"; else bad "the /proc scan did not flag our own test process (found $N)"; fi

line "5. firewall block / unblock (needs root + iptables or ufw)"

# a rule can live in iptables, nft or ufw depending on which one is really filtering
rule_present() {
  iptables -S 2>/dev/null | grep -q -- "$1" && return 0
  nft list ruleset 2>/dev/null | grep -q -- "$1" && return 0
  ufw status numbered 2>/dev/null | grep -q -- "$1" && return 0
  return 1
}

if [ "$NO_FIREWALL" = "1" ]; then
  echo "  skipped (--no-firewall)"
elif [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
  echo "  skipped (not root and no passwordless sudo) - run this script with sudo"
elif ! command -v iptables >/dev/null && ! command -v nft >/dev/null && ! command -v ufw >/dev/null; then
  echo "  skipped (no iptables / nft / ufw on this machine - apt install iptables ufw)"
else
  echo "  ufw state : $(ufw status 2>/dev/null | head -1 || echo 'ufw not installed')"
  echo "  iptables  : $(command -v iptables || echo 'not installed')   nft: $(command -v nft || echo 'not installed')"

  # --- 5a: rule really appears in the live firewall ---
  OUT="$(run_action block_access "$TEST_IP" | tr -d '\n')"
  sleep 0.5
  if rule_present "$TEST_IP"; then
    ok "rule for $TEST_IP exists in the live firewall"
  else
    bad "no rule found after block_access (output: $(echo "$OUT" | tail -c 200))"
  fi

  # --- 5b: packets are really dropped (only meaningful when iptables does both directions) ---
  REAL_IP="1.1.1.1"
  if command -v iptables >/dev/null && ! ufw status 2>/dev/null | grep -q "Status: active"; then
    BEFORE="$(curl -s -m 6 -o /dev/null -w '%{http_code}' http://$REAL_IP/ 2>/dev/null)"
    run_action block_access "$REAL_IP" >/dev/null 2>&1
    sleep 1
    AFTER="$(curl -s -m 6 -o /dev/null -w '%{http_code}' http://$REAL_IP/ 2>/dev/null)"
    run_action unblock_access "$REAL_IP" >/dev/null 2>&1
    sleep 1
    AGAIN="$(curl -s -m 6 -o /dev/null -w '%{http_code}' http://$REAL_IP/ 2>/dev/null)"
    if [ "$BEFORE" != "000" ] && [ "$AFTER" = "000" ] && [ "$AGAIN" != "000" ]; then
      ok "packets really dropped: $REAL_IP answered $BEFORE -> blocked ($AFTER) -> unblocked ($AGAIN)"
    else
      bad "packet test inconclusive: before=$BEFORE blocked=$AFTER after=$AGAIN"
    fi
  else
    echo "  (packet test skipped - ufw is the active filter, it only guards inbound)"
  fi

  # --- 5c: the rule is removed again ---
  run_action unblock_access "$TEST_IP" >/dev/null 2>&1
  sleep 0.3
  if rule_present "$TEST_IP"; then bad "rule still there after unblock_access"; else ok "unblock_access removed the rule again"; fi

  ui_remove() { iptables -D INPUT -s "$1" -j DROP 2>/dev/null; iptables -D OUTPUT -d "$1" -j DROP 2>/dev/null; ufw --force delete deny from "$1" to any >/dev/null 2>&1; }
  ui_remove "$TEST_IP"; ui_remove "$REAL_IP"
fi

line "6. account lock / unlock (needs root + useradd)"
if [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
  echo "  skipped (not root) - run with sudo to test this row"
elif ! command -v useradd >/dev/null; then
  echo "  skipped (useradd not installed - apt install passwd)"
else
  useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null
  if id "$TEST_USER" >/dev/null 2>&1; then
    OUT="$(run_action restrict_identity "$TEST_USER" | tr -d '\n')"
    STATE="$(passwd -S "$TEST_USER" 2>/dev/null | awk '{print $2}')"
    if [ "$STATE" = "L" ]; then ok "account $TEST_USER is LOCKED (passwd -S = L)"; else bad "account not locked (passwd -S = $STATE)"; fi
    run_action lift_restriction "$TEST_USER" >/dev/null 2>&1
    STATE="$(passwd -S "$TEST_USER" 2>/dev/null | awk '{print $2}')"
    if [ "$STATE" = "P" ]; then ok "account unlocked again (passwd -S = P)"; else bad "account still locked (passwd -S = $STATE)"; fi
    if [ "$KEEP_USER" = "0" ]; then userdel -r "$TEST_USER" 2>/dev/null; ok "test account deleted"; fi
  else
    bad "could not create the test account"
  fi
fi

line "7. guards refuse dangerous targets (must all be refused)"
REFUSED=0
for target in 127.0.0.1 ::1 localhost 1; do
  OUT="$(run_action block_access "$target" 2>/dev/null | tr -d '\n')"
  echo "$OUT" | grep -q '"status": "failed"' && REFUSED=$((REFUSED+1))
done
OUT="$(run_action terminate_process 1 | tr -d '\n')"
echo "$OUT" | grep -q '"status": "failed"' && REFUSED=$((REFUSED+1))
OUT="$(run_action revoke_identity root | tr -d '\n')"
echo "$OUT" | grep -q '"status": "failed"' && REFUSED=$((REFUSED+1))
if [ "$REFUSED" -ge 6 ]; then ok "all 6 dangerous targets were refused"; else bad "only $REFUSED of 6 dangerous targets were refused"; fi

line "8. auditd (kernel view) - optional"
if [ -f /var/log/audit/audit.log ] && [ -r /var/log/audit/audit.log ]; then
  ok "audit.log is readable - load audit-rules/aiboo.rules to get execve/ptrace detections"
else
  echo "  not available here (no readable /var/log/audit/audit.log)"
  echo "  to enable: apt install auditd && cp audit-rules/aiboo.rules /etc/audit/rules.d/ && augenrules --load"
fi

line "9. log detection on this machine's real logs"
"$PY" "$AGENT" --config "$CFG" --once --dry-run 2>&1 | tail -5

line "RESULT"
echo "  PASS: $PASS    FAIL: $FAIL"
echo "  audit trail written by this run: $WORK/actions.jsonl"
[ "$FAIL" -eq 0 ] && echo "  ALL REAL CHECKS PASSED" || echo "  SOME CHECKS FAILED - send this whole output"
rm -rf "$WORK"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
