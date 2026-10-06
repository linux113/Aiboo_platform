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
