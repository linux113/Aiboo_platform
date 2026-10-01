"""
gates/compliance_checks.py - turns this PC's security health into a
compliance report mapped to ISO/IEC 27001:2022 (Annex A) and NIST CSF 2.0.

Input:  the DevicePosture from gates/device_posture.py (read-only PowerShell
        check, every device_check_minutes) + recent TriGate history.
Output: a list of checks, each PASS / FAIL / WARN / UNKNOWN with the controls
        it supports, a plain-English fix, and an overall score 0-100.

The agent sends the report to the dashboard (POST /api/agent/compliance);
the Reports page shows it and can export it as CSV / PDF.

Note: this is a TECHNICAL evidence check for one endpoint. It supports an
ISO 27001 / NIST CSF assessment; it is not a certification by itself.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

PASS, FAIL, WARN, UNKNOWN = "pass", "fail", "warn", "unknown"

# id, title, ISO 27001:2022 Annex A controls, NIST CSF 2.0 subcategories, weight
CHECKS = [
    ("av_enabled", "Antivirus real-time protection is on",
     ["A.8.7 Protection against malware"], ["DE.CM-09", "PR.PS-05"], 3),
    ("av_up_to_date", "Antivirus definitions are up to date",
     ["A.8.7 Protection against malware", "A.8.8 Management of technical vulnerabilities"], ["PR.PS-02"], 2),
    ("firewall_on", "Windows Firewall is on for every profile",
     ["A.8.20 Networks security", "A.8.22 Segregation of networks"], ["PR.IR-01"], 3),
    ("os_updated", "Windows updates installed in the last 30 days",
     ["A.8.8 Management of technical vulnerabilities"], ["PR.PS-02", "ID.RA-01"], 3),
    ("disk_encrypted", "System drive is encrypted (BitLocker)",
     ["A.8.24 Use of cryptography", "A.7.10 Storage media"], ["PR.DS-01"], 2),
    ("uac_on", "User Account Control (UAC) is on",
     ["A.8.2 Privileged access rights"], ["PR.AA-05"], 2),
    ("audit_logon", "Failed and successful logons are audited (event 4625 / 4624)",
     ["A.8.15 Logging", "A.8.16 Monitoring activities"], ["PR.PS-04", "DE.CM-03"], 3),
    ("account_lockout", "Accounts lock after repeated wrong passwords",
     ["A.8.5 Secure authentication"], ["PR.AA-03"], 2),
    ("password_length", "Minimum password length is at least 8",
     ["A.5.17 Authentication information"], ["PR.AA-01"], 2),
    ("guest_disabled", "Built-in Guest account is disabled",
     ["A.5.18 Access rights", "A.8.2 Privileged access rights"], ["PR.AA-05"], 1),
    ("smb1_disabled", "Old SMBv1 file-sharing protocol is off",
     ["A.8.9 Configuration management"], ["PR.PS-01"], 2),
    ("rdp_exposure", "Remote Desktop is off (or deliberately managed)",
     ["A.8.20 Networks security", "A.8.5 Secure authentication"], ["PR.IR-01", "PR.AA-03"], 1),
    ("monitoring_agent", "Security monitoring agent is running (AiBoO)",
     ["A.8.16 Monitoring activities"], ["DE.CM-01", "DE.CM-09"], 2),
    ("log_integrity", "Security log was not cleared and auditing not changed (7 days)",
     ["A.8.15 Logging"], ["PR.PS-04", "DE.AE-02"], 2),
    ("incident_handling", "No unhandled high-risk TriGate alerts in the last 24 h",
     ["A.5.25 Assessment and decision on information security events",
      "A.5.26 Response to information security incidents"], ["RS.MA-01", "DE.AE-04"], 1),
]

FIX = {
    "av_enabled": "Turn on real-time protection: Windows Security > Virus & threat protection.",
    "av_up_to_date": "Update antivirus definitions: Windows Security > Virus & threat protection > Check for updates.",
    "firewall_on": "Turn on Windows Firewall for Domain, Private and Public: Windows Security > Firewall.",
    "os_updated": "Install Windows updates: Settings > Windows Update > Check for updates.",
    "disk_encrypted": "Turn on BitLocker / Device encryption (Settings > Privacy & security > Device encryption).",
    "uac_on": "Turn UAC back on: Control Panel > User Accounts > Change User Account Control settings.",
    "audit_logon": 'Admin cmd: auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
    "account_lockout": "Admin cmd: net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15",
    "password_length": "Admin cmd: net accounts /minpwlen:8  (12+ recommended)",
    "guest_disabled": "Admin cmd: net user Guest /active:no",
    "smb1_disabled": "Admin PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
    "rdp_exposure": "If nobody needs it: Settings > System > Remote Desktop > Off.",
    "monitoring_agent": "Start the AiBoO agent as Administrator.",
    "log_integrity": "Find out who cleared the log / changed auditing (see the TriGate card) and re-enable auditing.",
    "incident_handling": "Open Alerts, acknowledge and close the high-risk alerts (or mark them false alarm).",
}


def _status(value: Optional[bool]) -> str:
    return UNKNOWN if value is None else (PASS if value else FAIL)


def evaluate(posture: Any, memory: Any = None, monitoring: bool = True) -> list[dict]:
    p = posture
    results: dict[str, tuple[str, str]] = {}

    def g(attr):
        return getattr(p, attr, None) if p is not None else None

    av = g("av_enabled")
    results["av_enabled"] = (_status(av), ", ".join(g("antivirus_names") or []) or "")
    fresh = g("av_up_to_date")
    results["av_up_to_date"] = (UNKNOWN if av is False else _status(fresh), "")
    fw = g("firewall_off_profiles")
    results["firewall_on"] = (UNKNOWN if fw is None else (PASS if not fw else FAIL),
                              f"off: {', '.join(fw)}" if fw else "")
    days = g("last_update_days")
    results["os_updated"] = (UNKNOWN if days is None else PASS if days <= 30 else WARN if days <= 60 else FAIL,
                             f"last update {days} days ago" if days is not None else "")
    results["disk_encrypted"] = (_status(g("disk_encrypted")),
                                 "" if g("disk_encrypted") is not None else "BitLocker not available (Windows Home?)")
    results["uac_on"] = (_status(g("uac_enabled")), "")
    fail_a, succ_a = g("audit_logon_failure"), g("audit_logon_success")
    if fail_a is None:
        results["audit_logon"] = (UNKNOWN, "")
    elif fail_a and succ_a:
        results["audit_logon"] = (PASS, "success and failure")
    elif fail_a or succ_a:
        results["audit_logon"] = (WARN, "only " + ("failure" if fail_a else "success") + " audited")
    else:
        results["audit_logon"] = (FAIL, "no logon auditing")
    lt = g("lockout_threshold")
    results["account_lockout"] = (UNKNOWN if lt is None else FAIL if lt == 0 else PASS if lt <= 10 else WARN,
                                  "never locks" if lt == 0 else f"locks after {lt} attempts" if lt else "")
    pl = g("min_password_length")
    results["password_length"] = (UNKNOWN if pl is None else PASS if pl >= 8 else FAIL,
                                  f"minimum {pl} characters" if pl is not None else "")
    gu = g("guest_enabled")
    results["guest_disabled"] = (UNKNOWN if gu is None else (FAIL if gu else PASS), "")
    smb = g("smb1_enabled")
    results["smb1_disabled"] = (UNKNOWN if smb is None else (FAIL if smb else PASS), "")
    rdp = g("rdp_enabled")
    results["rdp_exposure"] = (UNKNOWN if rdp is None else (WARN if rdp else PASS),
                               "Remote Desktop is ON" if rdp else "")
    results["monitoring_agent"] = (PASS if monitoring else FAIL, "")

    if memory is not None:
        try:
            cleared = memory.count_events(pattern="log_cleared", hours=24 * 7)
            audit = memory.count_events(pattern="audit_policy_changed", hours=24 * 7)
            results["log_integrity"] = (FAIL if (cleared or audit) else PASS,
                                        f"{cleared} log clear(s), {audit} audit change(s)" if (cleared or audit) else "")
        except Exception:
            results["log_integrity"] = (UNKNOWN, "")
        try:
            high = sum(1 for e in memory.data.get("events", [])
                       if int(e.get("risk", 0)) >= 55 and _recent(e.get("ts"), 24))
            results["incident_handling"] = (PASS if high == 0 else WARN,
                                            f"{high} BLOCK-level alert(s) in 24 h - review them" if high else "")
        except Exception:
            results["incident_handling"] = (UNKNOWN, "")
    else:
        results["log_integrity"] = (UNKNOWN, "")
        results["incident_handling"] = (UNKNOWN, "")

    out = []
    for cid, title, iso, nist, weight in CHECKS:
        status, detail = results.get(cid, (UNKNOWN, ""))
        out.append({"id": cid, "title": title, "status": status, "detail": detail,
                    "iso27001": iso, "nist_csf": nist, "weight": weight,
                    "fix": FIX.get(cid, "") if status in (FAIL, WARN) else ""})
    return out


def _recent(ts: Any, hours: float) -> bool:
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        now = datetime.now(t.tzinfo) if t.tzinfo else datetime.now()
        return (now - t).total_seconds() <= hours * 3600
    except (TypeError, ValueError):
        return False


def score(checks: list[dict]) -> Optional[int]:
    """Weighted: pass = 1, warn = 0.5, fail = 0; unknown is left out."""
    total = got = 0.0
    for c in checks:
        if c["status"] == UNKNOWN:
            continue
        total += c["weight"]
        got += c["weight"] * (1.0 if c["status"] == PASS else 0.5 if c["status"] == WARN else 0.0)
    return None if total == 0 else int(round(100 * got / total))


def framework_summary(checks: list[dict]) -> dict:
    """Per framework: controls covered and how many of them are fully met."""
    out = {}
    for fw, key in (("ISO 27001:2022", "iso27001"), ("NIST CSF 2.0", "nist_csf")):
        controls: dict[str, list[str]] = {}
        for c in checks:
            for ctl in c[key]:
                cid = ctl.split(" ")[0]
                controls.setdefault(cid, []).append(c["status"])
        met = sum(1 for sts in controls.values() if sts and all(s == PASS for s in sts))
        failing = sorted(cid for cid, sts in controls.items() if FAIL in sts)
        known = [cid for cid, sts in controls.items() if any(s != UNKNOWN for s in sts)]
        out[fw] = {"controls": len(controls), "met": met, "failing": failing, "assessed": len(known),
                   "score": score([c for c in checks if c[key]])}
    return out


def build_report(posture: Any, memory: Any = None, endpoint: str = "", monitoring: bool = True) -> dict:
    checks = evaluate(posture, memory, monitoring)
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in (PASS, FAIL, WARN, UNKNOWN)}
    return {
        "endpoint": endpoint,
        "checked_at": datetime.now().astimezone().isoformat(),
        "score": score(checks),
        "counts": counts,
        "frameworks": framework_summary(checks),
        "checks": checks,
        "posture": posture.to_dict() if hasattr(posture, "to_dict") else {},
    }
