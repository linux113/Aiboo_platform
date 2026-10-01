"""
log_ingestion/windows_event_parser.py — pure helpers for Windows events.

Everything here is plain Python (no pywin32), so it can be unit-tested on
any OS. The WindowsEventIngestor uses it to:

  * pull the right fields out of each event (field positions follow the
    Microsoft event schemas — e.g. 4625 IpAddress is insert #19, not #18),
  * drop noise from built-in service accounts (SYSTEM, DWM-1, PC$ ...),
  * turn single failed logons into one HIGH "brute force" alert only when
    they repeat (default: 5 failures for the same user/IP in 5 minutes),
  * write a plain-English description that the agents show on the
    dashboard instead of generic "identity verification FAILED" text.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

LOGON_TYPES = {
    "2": "interactive (keyboard)",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock screen",
    "8": "network (clear-text)",
    "9": "new credentials (RunAs)",
    "10": "remote desktop (RDP)",
    "11": "cached credentials",
}

# NTSTATUS codes seen in 4625 / 4776 (SubStatus / Status)
FAILURE_REASONS = {
    "0xc000006a": "wrong password",
    "0xc0000064": "user name does not exist",
    "0xc000006d": "bad user name or password",
    "0xc0000072": "account is disabled",
    "0xc0000234": "account is locked out",
    "0xc000006f": "outside allowed logon hours",
    "0xc0000070": "workstation not allowed",
    "0xc0000071": "password expired",
    "0xc0000193": "account expired",
    "0xc0000224": "password must be changed",
    "0xc000015b": "logon type not granted",
    "0xc0000133": "clock out of sync with domain controller",
}

# Kerberos pre-auth failure codes (4771)
KERBEROS_FAILURES = {
    "0x18": "wrong password",
    "0x12": "account disabled, expired or locked out",
    "0x17": "password expired",
    "0x6": "user name does not exist",
}

# Built-in accounts that generate a constant stream of logon events and
# are never a person typing a password.
_SERVICE_ACCOUNT_NAMES = {
    "system", "local service", "network service", "anonymous logon",
    "localservice", "networkservice", "-", "", "unknown", "nt authority\\system",
}
_SERVICE_ACCOUNT_PREFIXES = ("dwm-", "umfd-", "font driver host", "window manager")

# Events where service-account noise is filtered out
_IDENTITY_EVENT_IDS = {4624, 4634, 4647, 4648, 4672, 4673, 4674, 4768, 4769, 4776}

# Failed-logon style events fed into the brute-force tracker
BRUTE_FORCE_EVENT_IDS = {4625, 4771, 4776}

# Scheduled-task content that makes a new task worth a HIGH alert
_SUSPICIOUS_TASK_MARKERS = (
    "powershell", "pwsh", "cmd.exe", "cmd /c", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "certutil", "bitsadmin", "http://", "https://",
    "\\temp\\", "-enc", "frombase64string",
)


# Groups whose membership really matters. Adding a user to "Users" or the
# workstation default group "None" happens automatically on every
# "net user X /add", so those are not alerts.
_PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "remote desktop users", "remote management users", "backup operators",
    "account operators", "server operators", "print operators",
    "hyper-v administrators", "dnsadmins", "group policy creator owners",
    "network configuration operators",
}


def is_privileged_group(group: Optional[str]) -> bool:
    return str(group or "").split("\\")[-1].strip().lower() in _PRIVILEGED_GROUPS


def _resolve_sid(sid: str) -> str:
    """Turn 'S-1-5-21-...-1005' into 'PC\\name' when running on Windows."""
    if not str(sid).upper().startswith("S-1-"):
        return sid
    try:
        import win32security  # type: ignore
        name, domain, _ = win32security.LookupAccountSid(
            None, win32security.ConvertStringSidToSid(sid))
        return f"{domain}\\{name}" if domain else name
    except Exception:
        return sid


def _get(strings: list, idx: int, default: str = "unknown") -> str:
    try:
        val = strings[idx]
    except (IndexError, TypeError):
        return default
    if val is None:
        return default
    val = str(val).strip()
    return val if val else default


def is_service_account(user: Optional[str]) -> bool:
    """True for SYSTEM / LOCAL SERVICE / DWM-1 / UMFD-0 / MACHINE$ etc."""
    u = (user or "").strip().lower()
    if "\\" in u:
        u = u.split("\\")[-1]
    if u in _SERVICE_ACCOUNT_NAMES:
        return True
    if u.endswith("$"):
        return True
    return u.startswith(_SERVICE_ACCOUNT_PREFIXES)


def _clean_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if ip in ("", "-", "::1", "127.0.0.1", "0.0.0.0", "::"):
        return "unknown"
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def _failure_reason(code: str) -> str:
    return FAILURE_REASONS.get((code or "").strip().lower(), code or "unknown reason")


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

def extract_fields(event_id: int, strings: list) -> dict:
    """
    Return the useful fields for one event (user_id, src_ip, ...), plus a
    plain-English ``description``. Unknown events get a generic description.
    """
    s = list(strings or [])
    f: dict = {}

    if event_id == 4625:  # Failed logon
        user = _get(s, 5)
        domain = _get(s, 6, "")
        reason = _failure_reason(_get(s, 9, "")) if _get(s, 9, "") not in ("", "0x0") \
            else _failure_reason(_get(s, 7, ""))
        logon_type = LOGON_TYPES.get(_get(s, 10, ""), f"type {_get(s, 10, '?')}")
        ip = _clean_ip(_get(s, 19, ""))
        workstation = _get(s, 13, "")
        f.update(user_id=user, domain=domain, src_ip=ip, failure_reason=reason,
                 logon_type=logon_type, workstation=workstation,
                 process_name=_get(s, 18, ""))
        where = f" from {ip}" if ip != "unknown" else ""
        f["description"] = f"Failed logon for '{user}' ({reason}, {logon_type}){where}"

    elif event_id == 4624:  # Successful logon
        user = _get(s, 5)
        ip = _clean_ip(_get(s, 18, ""))
        logon_type = LOGON_TYPES.get(_get(s, 8, ""), f"type {_get(s, 8, '?')}")
        f.update(user_id=user, domain=_get(s, 6, ""), src_ip=ip, logon_type=logon_type)
        where = f" from {ip}" if ip != "unknown" else ""
        f["description"] = f"Successful logon for '{user}' ({logon_type}){where}"

    elif event_id == 4648:  # Logon with explicit credentials
        actor = _get(s, 1)
        user = _get(s, 5)
        f.update(user_id=user, actor=actor, target_server=_get(s, 8, ""),
                 src_ip=_clean_ip(_get(s, 12, "")), process_name=_get(s, 11, ""))
        f["description"] = f"'{actor}' used explicit credentials of '{user}' (RunAs / saved credentials)"

    elif event_id == 4672:  # Special privileges assigned to new logon
        user = _get(s, 1)
        f.update(user_id=user, domain=_get(s, 2, ""))
        f["description"] = f"Administrator-level privileges assigned to '{user}' at logon"

    elif event_id in (4673, 4674):  # Sensitive privilege use
        user = _get(s, 1)
        proc = _get(s, 8, "") if event_id == 4673 else _get(s, 11, "")
        f.update(user_id=user, privilege=_get(s, 6, "") if event_id == 4673 else _get(s, 9, ""),
                 process_name=proc)
        f["description"] = f"Sensitive privilege used by '{user}'" + (f" via {proc}" if proc else "")

    elif event_id == 4740:  # Account locked out
        user = _get(s, 0)
        caller = _get(s, 1, "")
        f.update(user_id=user, caller_computer=caller, actor=_get(s, 4, ""))
        f["description"] = f"Account '{user}' was locked out after too many failed logons" + \
            (f" (caller: {caller})" if caller and caller != "unknown" else "")

    elif event_id in (4720, 4726):  # User created / deleted
        target = _get(s, 0)
        actor = _get(s, 4)
        verb = "created" if event_id == 4720 else "deleted"
        f.update(user_id=actor, actor=actor, target_user=target)
        f["description"] = f"User account '{target}' was {verb} by '{actor}'"

    elif event_id in (4728, 4732, 4756):  # Member added to security group
        member = _get(s, 0)
        if member in ("-", "unknown"):
            member = _get(s, 1)  # local groups often log only the member SID
        if member.upper().startswith("CN="):
            member = member.split(",")[0][3:]
        member = _resolve_sid(member)
        group = _get(s, 2)
        actor = _get(s, 6)
        f.update(user_id=actor, actor=actor, target_user=member, group=group,
                 privileged_group=is_privileged_group(group))
        f["description"] = f"'{member}' was added to group '{group}' by '{actor}'"

    elif event_id == 1102:  # Audit log cleared
        actor = _get(s, 1)
        f.update(user_id=actor, actor=actor)
        f["description"] = f"The Security audit log was cleared by '{actor}'"

    elif event_id == 4719:  # Audit policy changed
        actor = _get(s, 1)
        f.update(user_id=actor, actor=actor)
        f["description"] = f"System audit policy was changed by '{actor}'"

    elif event_id == 4697:  # Service installed (Security log)
        actor = _get(s, 1)
        name = _get(s, 4)
        path = _get(s, 5, "")
        f.update(user_id=actor, actor=actor, service_name=name, image_path=path)
        f["description"] = f"New service installed: '{name}'" + (f" ({path})" if path else "") + \
            f" by '{actor}'"

    elif event_id == 7045:  # Service installed (System log)
        name = _get(s, 0)
        path = _get(s, 1, "")
        account = _get(s, 4, "")
        f.update(service_name=name, image_path=path, service_account=account)
        f["description"] = f"New service installed: '{name}'" + (f" ({path})" if path else "")

    elif event_id == 4698:  # Scheduled task created
        actor = _get(s, 1)
        task = _get(s, 4)
        xml = _get(s, 5, "")
        m = re.search(r"<Command>(.*?)</Command>", xml, re.IGNORECASE | re.DOTALL)
        a = re.search(r"<Arguments>(.*?)</Arguments>", xml, re.IGNORECASE | re.DOTALL)
        command = (m.group(1).strip() if m else "")
        if a:
            command = f"{command} {a.group(1).strip()}".strip()
        f.update(user_id=actor, actor=actor, task_name=task, task_command=command[:300])
        f["description"] = f"Scheduled task '{task}' created by '{actor}'" + \
            (f" - runs: {command[:150]}" if command else "")

    elif event_id == 4688:  # Process creation
        user = _get(s, 1)
        proc = _get(s, 5, "")
        f.update(user_id=user, process_name=proc, command_line=_get(s, 8, ""))
        f["description"] = f"Process started by '{user}': {proc}"

    elif event_id == 4776:  # NTLM credential validation
        user = _get(s, 1)
        status = _get(s, 3, "0x0")
        f.update(user_id=user, workstation=_get(s, 2, ""), status=status,
                 failure_reason=_failure_reason(status) if status.lower() != "0x0" else "")
        f["description"] = (
            f"NTLM credential check failed for '{user}' ({_failure_reason(status)})"
            if status.lower() != "0x0" else f"NTLM credential check succeeded for '{user}'"
        )

    elif event_id == 4771:  # Kerberos pre-authentication failed
        user = _get(s, 0)
        code = _get(s, 4, "").lower()
        reason = KERBEROS_FAILURES.get(code, code or "unknown reason")
        ip = _clean_ip(_get(s, 6, ""))
        f.update(user_id=user, src_ip=ip, failure_reason=reason)
        f["description"] = f"Kerberos pre-authentication failed for '{user}' ({reason})" + \
            (f" from {ip}" if ip != "unknown" else "")

    elif event_id in (4768, 4769):  # Kerberos tickets
        user = _get(s, 0)
        ip = _clean_ip(_get(s, 9 if event_id == 4768 else 6, ""))
        f.update(user_id=user, src_ip=ip)
        f["description"] = f"Kerberos {'TGT' if event_id == 4768 else 'service ticket'} requested for '{user}'"

    elif event_id in (5140, 5145):  # Network share access
        user = _get(s, 1)
        share = _get(s, 7, "")
        f.update(user_id=user, src_ip=_clean_ip(_get(s, 5, "")), share_name=share)
        f["description"] = f"Network share {share or '?'} accessed by '{user}'"

    elif event_id in (5156, 5157, 5158):  # Windows Filtering Platform
        verb = {5156: "allowed", 5157: "BLOCKED", 5158: "allowed bind"}[event_id]
        app = _get(s, 1, "")
        f.update(process_name=app, src_ip=_clean_ip(_get(s, 3, "")),
                 dst_ip=_get(s, 5, ""), dst_port=_get(s, 6, ""))
        f["description"] = f"Firewall {verb} connection for {app or 'unknown app'}"

    return f


def task_is_suspicious(task_command: str) -> bool:
    cmd = (task_command or "").lower()
    return any(marker in cmd for marker in _SUSPICIOUS_TASK_MARKERS)


def should_drop(event_id: int, fields: dict) -> bool:
    """True for events that are pure noise and should never reach the agents."""
    if event_id in _IDENTITY_EVENT_IDS and is_service_account(fields.get("user_id")):
        return True
    # Successful NTLM validation happens on every normal logon
    if event_id == 4776 and str(fields.get("status", "0x0")).lower() == "0x0":
        return True
    return False


# ---------------------------------------------------------------------------
# Brute-force detection
# ---------------------------------------------------------------------------

class BruteForceTracker:
    """
    Counts failed logons per user and per source IP.

    A single wrong password is normal (typos). Only when the same user or
    the same IP fails ``threshold`` times inside ``window`` do we raise one
    HIGH alert — and then stay quiet for that key until the window passes.
    """

    def __init__(self, threshold: int = 5, window_seconds: int = 300) -> None:
        self.threshold = max(int(threshold), 2)
        self.window = timedelta(seconds=max(int(window_seconds), 30))
        self._hits: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, datetime] = {}

    def record(self, fields: dict, when: datetime) -> Optional[dict]:
        """
        Record one failure. Returns an info dict when the threshold is hit
        (``key``, ``count``, ``kind``), otherwise None.
        """
        keys = []
        user = fields.get("user_id")
        if user and user != "unknown" and not is_service_account(user):
            keys.append(("user", user.lower()))
        ip = fields.get("src_ip")
        if ip and ip != "unknown":
            keys.append(("ip", ip))

        result = None
        for kind, value in keys:
            key = f"{kind}:{value}"
            q = self._hits[key]
            q.append(when)
            cutoff = when - self.window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.threshold:
                last = self._last_alert.get(key)
                if last is None or when - last >= self.window:
                    self._last_alert[key] = when
                    if result is None:
                        result = {"key": value, "kind": kind, "count": len(q)}
        # keep memory bounded
        if len(self._hits) > 5000:
            for k in [k for k, q in self._hits.items() if not q][:2500]:
                self._hits.pop(k, None)
        return result
