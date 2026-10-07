# AiBoO Linux Sentinel

Read-only log agent that brings **Linux servers** into the same AiBoO dashboard as
your **Windows PCs**. One backend, one dashboard, one alert list — two operating
systems.

```
Windows PC    AiBoO-Agent.exe      reads the Windows Event Log
Linux server  aiboo_linux_agent.py reads auth.log / nginx / mysql / journalctl
                     \                    /
                      \                  /
                    AiBoO backend (Node)  ->  dashboard, alerts, approvals,
                                              playbooks, response rules, reports
```

## What it detects on Linux

| Area | Detection | AiBoO pattern | Typical severity |
|---|---|---|---|
| SSH | Failed password / invalid user, 5 in 5 min from one IP or for one user | `brute_force` | high |
| SSH | Successful logon **right after** ≥3 failures | `login_after_brute_force` | **critical** |
| SSH | POSSIBLE BREAK-IN ATTEMPT, no-identification probes, half-open floods | `network_intrusion` | medium/high |
| sudo | Dangerous commands run as root (`su`, `passwd`, `useradd`, `curl | sh`, `chattr`, `iptables`, …) | `suspicious_sudo` | high |
| Accounts | `useradd`, `userdel`, added to `sudo`/`wheel`/`adm` | `account_created`, `account_deleted`, `admin_group_add` | high |
| Persistence | `crontab` changed, `authorized_keys` modified | `scheduled_task`, `ssh_key_installed` | high |
| Hiding tracks | log truncated/deleted, auditd/rsyslog stopped | `log_cleared`, `audit_policy_changed` | **critical**/high |
| Web (Nginx) | SQL injection (union/OR 1=1/sleep/load_file…), XSS, path traversal | `sql_injection`, `xss_attempt`, `path_traversal` | critical/high |
| Web | Probes for `/.env`, `/.git`, backups, phpMyAdmin, `swagger` — and **served** secrets (HTTP 200) | `sensitive_file_probe` / `sensitive_file_hit` | high/**critical** |
| Web | `sqlmap`, `nikto`, `nmap`, `nuclei`, `gobuster`, … User-Agents | `scanner_activity` | high |
| Web | 404 flood, login-endpoint brute force, error flood, huge URLs, odd methods | `directory_scan`, `brute_force`, `error_burst`, `network_intrusion` | medium/high |
| MySQL | `Access denied for user …` bursts | `brute_force` | high |
| Bad IPs | request from an IP in your `blocklist.txt` | `threat_intel_alert` | high |
| Posture (every hour) | `PermitRootLogin yes`, SSH passwords allowed, no fail2ban, world-readable `.env`, services listening on 0.0.0.0 | `config_weakness` | low–high |

Everything is scored with the **same TriGate formula** the Windows agent uses:

```
risk = 0.30 × (100 − Trust) + 0.40 × Intent + 0.30 × Impact
≥75 critical · ≥55 high  → BLOCK (red)
≥35 medium               → HOLD  (approval)
<35                      → PASS  (log only)
```

Trust starts at 70 and is lowered/raised by what is readable without root
(PermitRootLogin, PasswordAuthentication, fail2ban installed…). Impact comes from
the endpoint's **importance** on the dashboard (Endpoints page) — the agent reads
it back every 2 minutes, so changing it in the UI changes the scoring.

## Install (no root needed)

```bash
# copy the folder to the server, then:
cd linux-agent
./install.sh --url http://<aibo-server>:4000 --key <AGENT_API_KEY> --name auroraa-prod-ubuntu
```

`install.sh` will: check Python 3.8+, copy the files to `~/aiboo-linux-agent`,
write `config.ini`, run the built-in parser test, do a **dry run on the real
logs**, check `<server>/health`, then install a **systemd --user** service
(no sudo). Read-only access to the logs is enough:

```bash
# if /var/log/auth.log is not readable, ask the server admin for the 'adm' group:
sudo usermod -aG adm <your-user>
```

## Run by hand

```bash
python3 aiboo_linux_agent.py --selftest          # parsers only, no server
python3 aiboo_linux_agent.py --once --dry-run    # read real logs, send nothing
python3 aiboo_linux_agent.py --replay /var/log/auth.log --dry-run
python3 aiboo_linux_agent.py                     # normal run (loop)
python3 aiboo_linux_agent.py --reset-state       # forget offsets/counters
python3 aiboo_linux_agent.py --capabilities      # what may this agent change here?
python3 aiboo_linux_agent.py --run-action list   # same, as JSON
python3 aiboo_linux_agent.py --run-action block_access --target 45.95.147.3
python3 aiboo_linux_agent.py --run-action pseudo_lock --target demo
python3 aiboo_linux_agent.py --run-action restore_pseudo_lock --target <lock id>
```

Remote actions from the dashboard also work in `--once` mode, which makes them
easy to test: queue the action in the UI, then run `--once` on the server.

## Everyday commands (the helper scripts)

Same idea as the `.bat` files on Windows - one file per job, no arguments needed
when you are in a hurry. They all work in the agent folder (`~/aiboo-linux-agent`
after `install.sh`), and none of them need root.

| Script | What it does | Windows equivalent |
|---|---|---|
| `./configure.sh` | asks the server address + API key, writes `config.ini`, then **tests** it (`/health` and a real heartbeat). Use it again any time the ngrok address changes | `configure.ps1` / `run_agent.bat /setup` |
| `./run_agent.sh` | starts it in the background (first run sets it up first). `--foreground` to watch the log instead | `run_agent.bat` |
| `./show_status.sh` | running? connected? last 15 log lines, capabilities, server reachable? `--brief` for one line | `show_status.bat` |
| `./stop_agent.sh` | stops the background copy and/or the service (`--background` / `--service`) | `stop_agent.bat` |
| `./install_service.sh` | always on: a systemd `--user` service that starts with the machine and restarts itself | `install_service.bat` |
| `./uninstall_service.sh` | removes that service (`--purge` also deletes config/logs/state) | `uninstall_service.bat` |

Typical use:

```bash
cd ~/aiboo-linux-agent
./configure.sh            # once: address + key, and it proves the connection
./run_agent.sh            # start now, in the background
./show_status.sh          # is it alive and talking to the dashboard?
./stop_agent.sh           # stop it
```

Always on (recommended on a real server):

```bash
./install_service.sh --linger     # --linger survives reboots/logouts (asks sudo once)
systemctl --user status aiboo-linux-agent
tail -f ~/aiboo-linux-agent/agent.log
```

`install.sh` copies these six scripts next to the agent automatically.

## Build a package to hand to a client (build_dist.sh)

On Windows the agent is compiled into `AiBoO-Agent.exe` + `dist.zip` with
`build_agent.bat`. **On Linux there is nothing to compile**: the agent uses only
the Python standard library (no pip packages), and every Linux server already has
`python3`. So "building" means packing the files into one archive.

```bash
cd linux-agent
./build_dist.sh                     # -> dist/aiboo-linux-agent-<version>.zip  (+ .tar.gz)
./build_dist.sh --with-tests        # also ship the test suite inside the package
./build_dist.sh --out /tmp/mystuff  # write it somewhere else
```

The script:

1. copies an explicit list of files (server code, the six helper scripts,
   `config.ini.example`, rules, blocklist, sudoers allowlist, auditd rules,
   README) into `aiboo-linux-agent-<version>/`,
2. **runs that copy with `--selftest`** so a broken build fails here, not on a
   client's server,
3. writes `BUILD_INFO.txt` (what it is, the 3 install commands, the fact that
   nothing is downloaded during install),
4. makes `.zip` (needs `zip`, falls back to Python) and `.tar.gz`, then tests
   the archive and prints its size and sha256.

It refuses to package `config.ini`, logs, saved state, the offline queue,
`actions.jsonl`, `quarantine/` or `state/` — a package can never leak one
server's settings or history.

On the new server (this is the whole deployment):

```bash
unzip aiboo-linux-agent-1.1.6.zip        # or:  tar xzf aiboo-linux-agent-1.1.6.tar.gz
cd aiboo-linux-agent-1.1.6
bash install.sh                          # asks for the dashboard address + API key
cd ~/aiboo-linux-agent
./run_agent.sh                           # or ./install_service.sh for always-on
```

Nothing is downloaded during install, so it also works on a server with no
internet access (copy the file over with `scp`, or hand it to the client).
`tar.gz` keeps the `+x` permission bits on every Linux; if you use the `.zip`
made on Windows, run `chmod +x *.sh` after unpacking.

## Files it creates (all in its own folder)

| File | Why |
|---|---|
| `config.ini` | settings |
| `linux-agent-state.json` | log offsets + counters + dedup (safe to delete) |
| `linux-agent-queue.jsonl` | findings that could not be sent (retried automatically) |
| `actions.jsonl` | every response action: time, action, target, result (your evidence trail) |
| `quarantine/` | files the agent moved out of the way (+ a `.json` with the sha256 and origin) |
| `state/restrictions.json` | accounts that are locked temporarily and when they unlock |
| `state/isolation.json` | a running full-isolation timer |

## Let the dashboard ACT on this server (optional)

Detection is always on. Changing things is **off by default** — one switch:

```ini
allow_response = yes        # config.ini
response_dry_run = yes      # first: record what WOULD happen, change nothing
```

Then restart the agent. `--capabilities` tells you what is possible:

```bash
python3 aiboo_linux_agent.py --capabilities
```

| Action the dashboard can send | What it does on Linux | Privilege needed |
|---|---|---|
| `block_access` / `isolate_asset` / `quarantine_device` | block that IP (`ufw deny` / `iptables -I INPUT -D DROP`, inbound **and** outbound) | root or sudo |
| `unblock_access` / `remove_throttle` | removes the rule again | root or sudo |
| `terminate_process` | `kill -9` by PID or exact name | root or sudo |
| `quarantine_file` | moves the file to `quarantine/<date>/…`, `chmod 000`, keeps sha256 + metadata | folder write access only |
| `restore_file` | puts it back (by path or sha256) | folder write access only |
| `revoke_identity` / `restrict_identity` | `usermod -L` + closes the user's sessions; `restrict` re-enables automatically after N minutes | root or sudo |
| `lift_restriction` | `usermod -U` | root or sudo |
| `step_up_auth` | closes the user's sessions so they must sign in again | root or sudo |
| `pseudo_lock` / `restore_pseudo_lock` | opens a **real decoy TCP port** (banner + payload capture) and closes it | none |
| `full_isolation` / `release_isolation` | only the AiBoO server can reach the host; auto-released (needs `allow_full_isolation = yes`) | root or sudo |

### Guard rails (always active)

* No `allow_response = yes` → every such action answers *"this server is in
  READ-ONLY mode"*; nothing is pretended.
* Never blocks `127.0.0.1`, `::1` or the **AiBoO server itself**.
* Never kills PID 1, `systemd*`, `sshd*`, `auditd`, `cron`, `rsyslogd` or the
  agent itself; a Python process can only be killed by explicit PID.
* Never locks `root`, system accounts (uid < 1000) or the account the agent runs as.
* Quarantine only touches `watch_dirs`, `/tmp`, `/var/tmp`, `/dev/shm`; symlinks
  and files > 100 MB are refused.
* Nothing runs through a shell, and every action is appended to `actions.jsonl`.

### Give the agent only what it needs

Prefer **not** running as root. Install the allowlist instead:

```bash
sudo visudo -c -f sudoers/aiboo-linux-agent.sudoers     # check
sudo sed -i 's/SERVICE_USER/aiboo/' sudoers/aiboo-linux-agent.sudoers
sudo cp sudoers/aiboo-linux-agent.sudoers /etc/sudoers.d/aiboo-linux-agent
sudo chmod 0440 /etc/sudoers.d/aiboo-linux-agent
```

## EDR-style collectors (kernel, processes, files)

| Collector | What it sees | Needs |
|---|---|---|
| **auditd** (`audit_log`) | every `execve` (like Windows 4688), `ptrace` / `process_vm_writev` (injection), root programs started from `/tmp` | read access to `/var/log/audit/audit.log`; install `audit-rules/aiboo.rules` (root, once) |
| **Process scan** (every 15 s) | reverse shells and C2 one-liners (`/dev/tcp/…`, `bash -i`, `nc -e`, `python -c import socket`, `curl … \| bash`), miners and attack tools (xmrig, nmap, hydra, sqlmap, pspy, chisel…), programs running from `/tmp`, `/dev/shm` | none (any user) |
| **File integrity** (every 5 min) | new/changed `.php/.jsp/.sh/.so…` files in `watch_dirs` with their sha256 — web shells and dropped payloads | read access to the folders |
| **Set-uid scan** (hourly, advisory) | unexpected set-uid binaries | none |
| **Decoy ports** | anyone who connects to a PseudoLock decoy, with the bytes they sent | none |

With `edr_kill_on_sight = yes` / `edr_quarantine_on_sight = yes` (both need
`allow_response = yes`) the agent reacts **by itself** to a reverse shell or a
dropped web shell — that is the closest thing to an EDR this agent does, and it
is still only these two well-defined cases.

Installing the audit rules (root, once) — this is what makes the kernel-level
detections work:

```bash
sudo cp audit-rules/aiboo.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | head
```

## What it still does NOT do

* No memory scanning and no kernel driver: nothing is injected, blocked or
  filtered inside the kernel.
* `full_isolation` blocks network traffic with the firewall — it is not a
  switch-port/NAC quarantine.
* No antivirus-style file scanning by signature (quarantine is rule-based, by
  location/extension and your own findings).
* It does not read the application's database, its `.env` or its secrets.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot read /var/log/auth.log` | your user needs the `adm` group (or `sudo` once to add it) |
| endpoint never shows Online | `remote_url` wrong, or port 4000 not open in the security group |
| `server said HTTP 401` | `api_key` must equal `AGENT_API_KEY` in the server's `backend/.env` |
| too many findings at first start | `--reset-state` then tune thresholds in `config.ini` |
| nothing detected although attacks run | check the log path in `config.ini` (`--once --dry-run` shows what is read) |
| action says *"needs root and no passwordless sudo"* | install `sudoers/aiboo-linux-agent.sudoers` or run the agent as root |
| action says *"READ-ONLY mode"* | `allow_response = yes` in `config.ini`, then restart the agent |
| no kernel-level findings | install auditd + `audit-rules/aiboo.rules`, and make sure `audit_log` is readable |
| want to see what an action would do | keep `response_dry_run = yes` and read `actions.jsonl` |

### Firewall choices (and one honest warning)

AiBoO picks the tool that is **really filtering traffic** on the server:

| Situation | What AiBoO uses | What the dashboard says |
|---|---|---|
| iptables/nft present | `iptables -I INPUT -s IP -j DROP` (and OUTPUT) | `blocked 45.95.147.3 with iptables` |
| ufw installed **and enabled** | `ufw deny from IP to any` | `blocked ... with ufw` |
| ufw installed but **inactive** (normal on AWS) | iptables/nft, if present | `blocked ... with iptables` |
| ufw only, and it is switched off | ufw (rule stored, not enforced) | `blocked ... WARNING: ufw is NOT enabled - rule stored, traffic not dropped yet` |

A rule added to a switched-off ufw drops nothing, so AiBoO never silently claims a
block it did not make. AiBoO also never enables ufw itself - that can cut the SSH
session you are working over.

IPv6 targets (`2001:db8::1`) are blocked with `ip6tables`; if the server has no
`ip6tables`, the action fails and says so instead of pretending.

### What AiBoO will always refuse

Not a single firewall, kill or lock command is built for these targets - they are
refused before any command runs:

| Refused target | Why |
|---|---|
| `localhost`, `127.0.0.1`, `127.x.x.x`, `::1` | would cut the server's own loopback traffic |
| `169.254.169.254` (link-local) | cloud metadata service (AWS credentials live there) |
| `0.0.0.0/0`, `255.255.255.255`, multicast/unspecified | would cut off everything, including AiBoO |
| any network that contains the AiBoO server IP | the server would stop reporting to the dashboard |
| `1`, `example.com`, text, empty strings | not an IP address - nothing to block |
| PID 1, `systemd*`, `sshd*`, `auditd`, `cron`, `rsyslogd`, the agent itself | killing these takes the server down |
| `root`, uid < 1000, the agent's own user | locking these locks out the admins |

Lock and unlock also **verify their own result** with `passwd -S`. An account with
no password at all cannot be "unlocked" (that would allow login with an empty
password) - AiBoO reports that honestly and tells you to run `passwd <user>` first.

### Set-uid binaries: baseline first, alarms only for changes

On a normal Linux server, set-uid binaries are everywhere (`/usr/bin/passwd`,
`sudo`, `mount`, `fusermount3`, ...) - that is how Linux works. Reporting all of
them drowns the real alerts, so the first scan only **records a baseline** (shown
in the log as `set-uid baseline recorded: N known binaries`) and stays quiet.

After that AiBoO speaks up only when a set-uid binary **appears**:

| Where the new binary sits | Severity | Raises a HOLD? |
|---|---|---|
| `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/srv`, `/var/www`, `/run` | **high** | yes - this is where attackers drop privesc binaries |
| `/opt` or another non-system path | medium | no (advisory) |
| `/usr/bin`, `/usr/sbin`, `/bin`, ... | medium, marked "new since the last scan" | no (advisory) |

The baseline lives in `linux-agent-state.json`. Delete that file (or run with
`--reset-state`) to make the agent learn the server from scratch again.

### Troubleshooting: HTTP 502 from the server

A 502 usually comes from the tunnel (ngrok free URLs go offline when the tunnel
process stops, and ngrok answers 502 while it cannot reach your backend). AiBoO
does **not** lose those findings: anything the server refuses goes into
`linux-agent-queue.jsonl` and is re-sent automatically on the next run and on
every poll afterwards. Check the queue with:

    wc -l linux-agent-queue.jsonl

If it keeps growing, the server address or key is wrong, or the backend is down.
Check the tunnel itself from the server:

    curl -s -o /dev/null -w '%{http_code}\n' https://YOUR-TUNNEL.ngrok-free.app/health

`200` = the tunnel is fine; `502` = ngrok cannot reach your backend (restart the
tunnel, or the backend); `000` = no connection at all.

### False positives: what was fixed after the first live run

The first live Ubuntu server showed how easy it is to alarm on normal Linux work.
These were real bugs and are fixed (each one has a test):

| What happened | Why | Fix |
|---|---|---|
| `strip -g -p /var/tmp/dracut.…` and `cp --reflink=auto …` reported as **critical reverse shell** | the matcher accepted a bare tool name (`mkfifo`, `chmod +x /tmp`) with no network step | a reverse shell now needs the real shape: `/dev/tcp`, `nc -e`, `socat … exec:`, `mkfifo … \| sh`, `curl … \| sh`, `python -c import socket`, ... |
| `cp --reflink=auto -dfrp -L -t …` reported as an **attack tool** | the tool list matched plain substrings, so `"frp "` matched inside `-dfrp` | tools are matched as whole tokens (`pspy64` still matches `pspy`) |
| Ubuntu **kernel/package work** in `/var/tmp/dracut.*` reported as "root ran a program from /tmp" | package managers legitimately build there | `dracut`, `initramfs`, `dpkg`, `apt`, `mkinitramfs` work is recognised as maintenance and skipped |
| `sudo umount` / `sudo apt-get install curl` reported as **dangerous sudo** | substrings again (`"mount "` inside `umount`) | whole-token matching, and package-manager commands are ignored |
| AiBoO **alerted on its own actions** (`usermod -L`, `iptables -I`, `ufw deny` it had just run) | the agent reads the same sudo/audit logs it writes to | the response engine records what it really ran and the detectors ignore those lines for 2 minutes |

Real events still raise alerts, by design: a **root shell** (`sudo bash …`),
`chpasswd`/`usermod`/`userdel`, `iptables`/`ufw` used by a human, log truncation.

**Running `tests/prove_real.sh` creates real account events** (`useradd` →
`userdel` → `chpasswd` for its test account) plus a `sudo bash` line. Those alerts
are correct - close or acknowledge them after a test run.

### A fresh install never replays old history

On the first run of a new install (or after deleting `linux-agent-state.json`) the
agent starts at the **last 30 minutes** of each log instead of the beginning. Before
this, a new install re-read the whole `auth.log`, so weeks-old admin commands came
back as brand-new alerts.

    12:53:53 [INFO] first read of /var/log/auth.log: starting at the last 30
                    minute(s) of activity (use --replay /var/log/auth.log to
                    analyse the whole file)

Change the window with `first_run_lookback_minutes = 30` in `config.ini`
(`0` = never skip anything). To deliberately analyse an entire file, use
`--replay /var/log/auth.log` - that mode always reads the whole file.

### The installer checks your API key before it starts

`install.sh` now refuses obvious placeholders (`YOUR-AGENT-KEY`, `CHANGEME`, ...)
and, when the server answers, sends a real heartbeat to prove the key is accepted:

    [OK] the server ACCEPTED the API key (heartbeat sent as 'aiboo-linux-01')

    [!] The server REJECTED the API key (HTTP 401). Nothing will reach the
        dashboard until this is fixed.

If you installed with a wrong key, copy the working one and restart:

    KEY=$(grep -m1 '^api_key' ~/aiboo/linux-agent/config.ini | cut -d= -f2- | sed 's/^ *//')
    sed -i "s|^api_key =.*|api_key = $KEY|" ~/aiboo-linux-agent/config.ini
    systemctl --user restart aiboo-linux-agent
    journalctl --user -u aiboo-linux-agent -n 5 --no-pager

### Server posture findings (config_weakness) go out once a day

Things like "No fail2ban installed" or "SSH MaxAuthTries is not set" describe the
state of the server, not an event. They are reported **once per day**, are always
low/medium, and never create a HOLD or BLOCK. Fix one (install fail2ban, set
MaxAuthTries) and the reminder simply stops.

### Attack demo (prove the detections on a real server)

    sudo bash tests/attack_demo.sh --config ~/aiboo-linux-agent/config.ini

Phase 1 replays an attack log (nothing on the server is touched): SSH brute force,
a login right after it, a `truncate -s 0 /var/log/auth.log`, a SQL injection and a
`/.env` download. Phase 2 creates real events: a PHP web shell in the web root, a
set-uid binary in /tmp, a reverse-shell process for 30 seconds, and a log-wipe
command. Everything it creates is removed when it exits.

Expected on the dashboard: HIGH `brute_force`, CRITICAL `login_after_brute_force`
and `log_cleared` (BLOCK), HIGH `sql_injection` / `sensitive_file_hit` (BLOCK),
HIGH `dropped_file` (the web shell), HIGH `suid_binary` (the /tmp binary) and
CRITICAL `reverse_shell` (the process).

Use `--phase1` to run only the harmless part. Re-running the demo shows nothing new
because the events were already sent (that is the dedup working): run
`python3 aiboo_linux_agent.py --config … --reset-state` first to see it again.
