#!/usr/bin/env bash
# AiBoO Linux Sentinel - build the distributable package (the Linux equivalent
# of agent/build_agent.bat -> dist.zip on Windows).
#
#   ./build_dist.sh                 make dist/aiboo-linux-agent-<version>.zip (+ .tar.gz)
#   ./build_dist.sh --with-tests    also ship the test suite inside the package
#   ./build_dist.sh --out /tmp/x    write the files somewhere else
#
# Why there is no compiler step here (unlike Windows): the Linux agent uses ONLY
# the Python standard library - no pip packages, no .exe. Every Linux server
# already has python3, so the package is simply the files + the helper scripts.
#
# The script also RUNS the packaged copy (--selftest) before it packs it, so a
# broken build fails here instead of on a client's server.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/dist"
WITH_TESTS=0
KEEP_STAGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --with-tests) WITH_TESTS=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --keep-staging) KEEP_STAGE=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "[ERROR] Python 3 is not installed (apt install python3)"; exit 1; }

VERSION="$("$PY" - "$DIR/aiboo_linux_agent.py" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)', src, re.M)
print(m.group(1) if m else "0.0.0")
PY
)"
PKG="aiboo-linux-agent-$VERSION"
STAGE="$OUT/$PKG"

echo "=========================================================="
echo "  AiBoO Linux Sentinel - build the dist package"
echo "=========================================================="
echo "  source : $DIR"
echo "  version: $VERSION"
echo "  output : $OUT"
echo

# ---- 1. what goes in (an explicit list - never 'copy everything') -----------
FILES=(
  aiboo_linux_agent.py
  aiboo_linux_response.py
  config.ini.example
  rules.json
  blocklist.txt
  README.md
  install.sh
  configure.sh
  run_agent.sh
  show_status.sh
  stop_agent.sh
  install_service.sh
  uninstall_service.sh
  aiboo-linux-agent.service
)
DIRS=(
  sudoers
  audit-rules
)

for f in "${FILES[@]}"; do
  [ -f "$DIR/$f" ] || { echo "[ERROR] missing file: $f"; exit 1; }
done
for d in "${DIRS[@]}"; do
  [ -d "$DIR/$d" ] || { echo "[ERROR] missing folder: $d"; exit 1; }
done

# ---- 2. stage ---------------------------------------------------------------
echo "[1/5] staging $PKG ..."
rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in "${FILES[@]}"; do cp -p "$DIR/$f" "$STAGE/"; done
for d in "${DIRS[@]}"; do cp -rp "$DIR/$d" "$STAGE/"; done
if [ "$WITH_TESTS" = "1" ] && [ -d "$DIR/tests" ]; then
  mkdir -p "$STAGE/tests"
  cp -p "$DIR/tests/"*.py "$STAGE/tests/" 2>/dev/null || true
  cp -p "$DIR/tests/"*.sh "$STAGE/tests/" 2>/dev/null || true
fi
chmod +x "$STAGE"/*.sh
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Nothing private or machine-specific may travel in the package. This runs
# again after the self test below: running the agent creates config.ini and
# __pycache__ in its own folder, so the second check is the one that matters.
clean_stage() {
  find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  rm -f "$STAGE"/config.ini "$STAGE"/config.ini.tmp "$STAGE"/agent.log "$STAGE"/agent.pid \
        "$STAGE"/linux-agent-state.json "$STAGE"/linux-agent-queue.jsonl "$STAGE"/actions.jsonl 2>/dev/null || true
  rm -rf "$STAGE"/quarantine "$STAGE"/state 2>/dev/null || true
}
check_stage() {
  local bad found=0
  for bad in config.ini linux-agent-state.json linux-agent-queue.jsonl actions.jsonl agent.log agent.pid; do
    if [ -e "$STAGE/$bad" ]; then echo "[ERROR] refusing to package a runtime file: $bad"; found=1; fi
  done
  for bad in quarantine state __pycache__; do
    if [ -e "$STAGE/$bad" ]; then echo "[ERROR] refusing to package runtime folder: $bad"; found=1; fi
  done
  [ "$found" = "0" ] || exit 1
}
clean_stage
check_stage
echo "      $(find "$STAGE" -type f | wc -l) files"

# ---- 3. prove the packaged copy runs ---------------------------------------
echo "[2/5] running the packaged copy (--selftest, no server needed) ..."
if ! "$PY" "$STAGE/aiboo_linux_agent.py" --selftest > "$OUT/.selftest.log" 2>&1; then
  echo "[ERROR] the packaged agent failed its own self test:"
  tail -20 "$OUT/.selftest.log" | sed 's/^/        /'
  exit 1
fi
SELFTEST_LAST="$(grep -E 'PASS|OK|failed|FAIL' "$OUT/.selftest.log" | tail -1 || true)"
echo "      ${SELFTEST_LAST:-selftest ok}"
# now throw away whatever the self test wrote and re-check the package is clean
clean_stage
check_stage

# ---- 4. the version/notes file inside the package --------------------------
date_str="$(date -u '+%Y-%m-%d %H:%M UTC')"
cat > "$STAGE/BUILD_INFO.txt" <<INFO
AiBoO Linux Sentinel - package $VERSION
built $date_str from $DIR

What this is
  The AiBoO agent for LINUX servers: it reads this machine's logs and sends
  what it finds to your AiBoO dashboard, and (if you allow it) it can block an
  IP, kill a process or quarantine a file when you press a button there.

No installation of extra software is needed: it uses only Python 3.8+.
Every Linux server already has python3.

Install in 3 commands (as the user who should run the agent)
    bash install.sh                 # asks for the dashboard address + API key
    cd ~/aiboo-linux-agent          # install.sh copies everything there
    ./run_agent.sh                  # start it (or ./install_service.sh = always on)

The everyday helper scripts (all in the installed folder)
    ./configure.sh        change the dashboard address / API key (tests it too)
    ./run_agent.sh        start in the background   (--foreground to watch)
    ./show_status.sh      running? connected? last log lines
    ./stop_agent.sh       stop it
    ./install_service.sh  always on, starts with the machine
    ./uninstall_service.sh  remove that service

Detection only by default: allow_response = no. The dashboard cannot change
this server until you set it to yes (see README, section "Let the dashboard
ACT on this server").

Nothing here contains a password or a key: the API key is written into
config.ini by install.sh / configure.sh on the machine itself.
INFO

# ---- 5. pack ---------------------------------------------------------------
echo "[3/5] packing ..."
mkdir -p "$OUT"
rm -f "$OUT/$PKG.zip" "$OUT/$PKG.tar.gz"

if command -v zip >/dev/null 2>&1; then
  ( cd "$OUT" && zip -qr "$PKG.zip" "$PKG" )
else
  "$PY" - "$OUT" "$PKG" <<'PY'
import os, sys, zipfile
out, pkg = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(os.path.join(out, pkg + ".zip"), "w", zipfile.ZIP_DEFLATED) as z:
    for root, _dirs, files in os.walk(os.path.join(out, pkg)):
        for name in files:
            full = os.path.join(root, name)
            z.write(full, os.path.relpath(full, out))
print("      (python zipfile was used - 'zip' is not installed)")
PY
fi
tar -czf "$OUT/$PKG.tar.gz" -C "$OUT" "$PKG"

ZIP_SIZE="$(du -h "$OUT/$PKG.zip" | cut -f1)"
TAR_SIZE="$(du -h "$OUT/$PKG.tar.gz" | cut -f1)"
SHA="$(sha256sum "$OUT/$PKG.zip" | cut -d' ' -f1)"

echo "[4/5] checking the archive can be read ..."
if command -v unzip >/dev/null 2>&1; then
  unzip -tqq "$OUT/$PKG.zip" && echo "      zip OK ($(unzip -Z1 "$OUT/$PKG.zip" | grep -vc '/$') files)"
else
  "$PY" -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); bad=z.testzip(); print('      zip OK' if bad is None else 'BAD: '+str(bad))" "$OUT/$PKG.zip"
fi
echo "[5/5] done"

[ "$KEEP_STAGE" = "1" ] || rm -rf "$STAGE"
rm -f "$OUT/.selftest.log"

echo
echo "=========================================================="
echo "  BUILD OK - version $VERSION"
echo "=========================================================="
echo "  $OUT/$PKG.zip      ($ZIP_SIZE)"
echo "  $OUT/$PKG.tar.gz   ($TAR_SIZE)   <- keeps the +x bits on every Linux"
echo
echo "  sha256 (zip): $SHA"
echo
echo "  Inside the package:"
( cd "$OUT" && [ -d "$PKG" ] && ls "$PKG" || "$PY" -c "
import zipfile,sys
names=[n for n in zipfile.ZipFile(sys.argv[1]).namelist() if not n.endswith('/')]
top=sorted({n.split('/')[1] for n in names if len(n.split('/'))>1})
for t in top: print('    '+t)
" "$OUT/$PKG.zip" ) | sed 's/^/  /'
echo
echo "  Send it to a server (from this machine):"
echo "      scp $OUT/$PKG.zip user@server:/tmp/"
echo
echo "  On that server:"
echo "      sudo apt install -y unzip            # once, if unzip is missing"
echo "      cd /tmp"
echo "      unzip $PKG.zip"
echo "      cd $PKG"
echo "      bash install.sh                      # asks address + key, then sets up"
echo "      cd ~/aiboo-linux-agent && ./run_agent.sh"
echo
echo "  No internet from that server? The zip is self-contained - nothing is"
echo "  downloaded during install."
echo
