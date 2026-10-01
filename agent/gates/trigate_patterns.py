"""
gates/trigate_patterns.py - shared helpers for the TriGate (Trust / Intent / Impact).

* classify(event)      -> which attack pattern an event is (brute force, log
                          cleared, new admin, ...), with a MITRE ATT&CK id and
                          a base intent score.
* ip_kind(ip)          -> "public" / "private" / "local" / "none"
* local_time(ts)       -> the event time in the PC's own time zone
* parse_business_hours -> "8-20" -> (8, 20)

Everything here is pure (no I/O) so it is easy to unit-test.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

# Commands / paths that make a service, task or process look like an attack
SUSPICIOUS_COMMAND_MARKERS = (
    "powershell", "pwsh", "cmd.exe", "cmd /c", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "http://", "https://",
    "\\temp\\", "\\appdata\\", "\\users\\public\\", "-enc", "frombase64string",
)

# Windows logon types (text produced by windows_event_parser.LOGON_TYPES)
REMOTE_LOGON_MARKERS = ("network", "remote desktop", "rdp")
LOCAL_LOGON_MARKERS = ("interactive", "unlock", "cached")


@dataclass(frozen=True)
class Pattern:
    key: str             # machine name, e.g. "brute_force"
    label: str           # plain English for the dashboard
    base_intent: int     # 0-100 starting point for Gate 2
    mitre_id: str = ""
    mitre_name: str = ""
    persistence: bool = False      # survives reboot (service / task)
    admin_rights: bool = False     # touches administrator rights
    evidence: bool = False         # destroys evidence / blinds monitoring


PATTERNS: dict[str, Pattern] = {p.key: p for p in [
    Pattern("brute_force", "Password guessing (many failed logons)", 70,
            "T1110", "Brute Force"),
    Pattern("failed_logon", "Failed logon", 30, "T1110", "Brute Force"),
    Pattern("account_lockout", "Account locked out", 55, "T1110", "Brute Force"),
    Pattern("log_cleared", "Security log cleared", 90,
            "T1070.001", "Indicator Removal: Clear Windows Event Logs", evidence=True),
    Pattern("audit_policy_changed", "Audit policy changed", 75,
            "T1562.002", "Impair Defenses: Disable Windows Event Logging", evidence=True),
    Pattern("admin_group_add", "User added to an admin group", 75,
            "T1098", "Account Manipulation", admin_rights=True),
    Pattern("group_add", "User added to a normal group", 20,
            "T1098", "Account Manipulation"),
    Pattern("account_created", "New user account created", 50,
            "T1136.001", "Create Account: Local Account"),
    Pattern("account_deleted", "User account deleted", 40,
            "T1531", "Account Access Removal"),
    Pattern("service_installed", "New service installed", 55,
            "T1543.003", "Create or Modify System Process: Windows Service", persistence=True),
    Pattern("scheduled_task", "Scheduled task created", 45,
            "T1053.005", "Scheduled Task/Job: Scheduled Task", persistence=True),
    Pattern("explicit_credentials", "Logon with someone else's password (RunAs)", 35,
            "T1078", "Valid Accounts"),
    Pattern("admin_logon", "Administrator privileges used at logon", 15,
            "T1078", "Valid Accounts", admin_rights=True),
    Pattern("process_started", "Process started", 20, "T1059", "Command and Scripting Interpreter"),
    Pattern("network_share", "Network share accessed", 25, "T1021.002", "Remote Services: SMB"),
    Pattern("firewall_event", "Firewall connection event", 20, "", ""),
    Pattern("network_intrusion", "Network intrusion", 55, "T1046", "Network Service Discovery"),
    Pattern("identity_mismatch", "Identity problem", 40, "T1078", "Valid Accounts"),
    Pattern("insider_threat", "Insider activity", 45, "", ""),
    Pattern("malware", "Malware", 80, "T1204", "User Execution"),
    Pattern("phishing", "Phishing", 60, "T1566", "Phishing"),
    Pattern("anomalous_behavior", "Unusual behaviour", 40, "", ""),
    Pattern("physical_intrusion", "Physical intrusion", 50, "", ""),
    Pattern("generic", "Security event", 30, "", ""),
]}

# Severity chosen on the Send Event tab -> base intent for test events
_TEST_SEVERITY_INTENT = {"low": 25, "medium": 45, "high": 65, "critical": 80}


def _val(x: Any) -> str:
    return str(getattr(x, "value", x) or "")


def command_is_suspicious(text: str) -> bool:
    t = (text or "").lower()
    return any(m in t for m in SUSPICIOUS_COMMAND_MARKERS)


def classify(event: Any) -> Pattern:
    """Return the attack pattern for a ThreatEvent (works for any event)."""
    p = getattr(event, "payload", None) or {}
    eid = p.get("event_id_raw")
    try:
        eid = int(eid) if eid not in (None, "") else None
    except (TypeError, ValueError):
        eid = None

    if p.get("brute_force") or int(_num(p.get("failed_attempts"))) >= 5:
        return PATTERNS["brute_force"]
    if eid in (4625, 4771, 4776):
        return PATTERNS["failed_logon"]
    if eid == 4740:
        return PATTERNS["account_lockout"]
    if eid == 1102:
        return PATTERNS["log_cleared"]
    if eid == 4719:
        return PATTERNS["audit_policy_changed"]
    if eid in (4728, 4732, 4756):
        return PATTERNS["admin_group_add"] if p.get("privileged_group") else PATTERNS["group_add"]
    if eid == 4720:
        return PATTERNS["account_created"]
    if eid == 4726:
        return PATTERNS["account_deleted"]
    if eid in (4697, 7045):
        return PATTERNS["service_installed"]
    if eid == 4698:
        return PATTERNS["scheduled_task"]
    if eid == 4648:
        return PATTERNS["explicit_credentials"]
    if eid == 4672:
        return PATTERNS["admin_logon"]
    if eid == 4688:
        return PATTERNS["process_started"]
    if eid in (5140, 5145):
        return PATTERNS["network_share"]
    if eid in (5156, 5157, 5158):
        return PATTERNS["firewall_event"]

    tt = _val(getattr(event, "threat_type", "")).lower()
    return PATTERNS.get(tt, PATTERNS["generic"])


def test_event_intent(event: Any) -> Optional[int]:
    """Base intent for a dashboard test event (from its chosen severity)."""
    p = getattr(event, "payload", None) or {}
    if not p.get("test_event"):
        return None
    return _TEST_SEVERITY_INTENT.get(_val(getattr(event, "severity", "")).lower(), 45)


def _num(x: Any) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def clean(value: Any) -> str:
    """'' for empty / placeholder values ('unknown', '-')."""
    v = str(value or "").strip()
    return "" if v.lower() in ("", "-", "unknown", "none", "null", "?") else v


def ip_kind(ip: Any) -> str:
    """'public', 'private', 'local' or 'none'."""
    v = clean(ip)
    if not v:
        return "none"
    try:
        addr = ipaddress.ip_address(v.split("%")[0])
    except ValueError:
        return "none"
    if addr.is_loopback or addr.is_unspecified:
        return "local"
    if addr.is_private or addr.is_link_local:
        return "private"
    return "public"


def logon_kind(logon_type: Any) -> str:
    """'remote', 'clear_text', 'runas', 'local' or '' from the parser's logon text."""
    t = str(logon_type or "").lower()
    if not t:
        return ""
    if "clear-text" in t:
        return "clear_text"
    if "runas" in t or "new credentials" in t:
        return "runas"
    if any(m in t for m in REMOTE_LOGON_MARKERS):
        return "remote"
    if any(m in t for m in LOCAL_LOGON_MARKERS):
        return "local"
    return ""


def local_time(ts: Any) -> datetime:
    """Event time in this PC's local time zone (naive datetimes are already local)."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts
        return ts.astimezone()            # convert UTC -> local
    return datetime.now()


def parse_business_hours(text: Any, default: tuple[int, int] = (8, 20)) -> tuple[int, int]:
    """'8-20' -> (8, 20). Hours are 0-23; start must be before end."""
    try:
        a, b = str(text).replace(" ", "").split("-", 1)
        start, end = int(a), int(b)
        if 0 <= start < end <= 24:
            return start, end
    except (ValueError, AttributeError):
        pass
    return default


def is_business_hours(dt: datetime, hours: tuple[int, int]) -> bool:
    start, end = hours
    return start <= dt.hour < end


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Settings from config.ini (set once by the orchestrator)
#   business_hours = 8-20      working hours for off-hours / working-hours checks
#   importance     = normal    default importance of this PC (low/normal/high/critical)
# ---------------------------------------------------------------------------
@dataclass
class TriGateSettings:
    business_hours: tuple = (8, 20)
    default_importance: str = "normal"


_settings = TriGateSettings()


def get_settings() -> TriGateSettings:
    return _settings


def configure_settings(business_hours: Any = None, importance: Any = None) -> TriGateSettings:
    global _settings
    from gates.trigate_memory import normalize_importance
    _settings = TriGateSettings(
        business_hours=parse_business_hours(business_hours) if business_hours else (8, 20),
        default_importance=normalize_importance(importance) or "normal",
    )
    return _settings
