"""
core/local_events.py — helpers for events read from this PC's own logs.

Windows Event Log records are facts ("5 failed logons for bob", "the
audit log was cleared"). They carry no identity factors (token,
biometrics, behaviour profile), so running them through identity
verification only produced false "verification FAILED" alerts.

Rule: exactly ONE agent turns a Windows event into a finding, and the
finding simply describes what Windows recorded.
"""

from __future__ import annotations

import ipaddress

from core.events import AgentFinding, ResponseAction, Severity, ThreatEvent

WINDOWS_SOURCE_PREFIX = "windows_event_log"

_DEFAULT_CONFIDENCE = {
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 0.9,
}


def is_windows_event(event: ThreatEvent) -> bool:
    return str(getattr(event, "source", "") or "").startswith(WINDOWS_SOURCE_PREFIX)


def _is_public_ip(value) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local)


def describe_windows_event(payload: dict) -> str:
    desc = payload.get("description")
    if desc:
        return str(desc)
    return (f"Windows event {payload.get('event_id_raw', '?')} in the "
            f"{payload.get('log_name', '?')} log on {payload.get('computer_name', '?')}")


def windows_event_finding(agent_name: str, event: ThreatEvent) -> AgentFinding:
    """Build the single finding for a Windows event."""
    p = event.payload or {}
    severity = event.severity
    confidence = _DEFAULT_CONFIDENCE.get(severity, 0.5)
    if p.get("brute_force"):
        # more failures = more certain it's not a typo
        confidence = min(0.6 + 0.03 * int(p.get("failed_attempts", 5)), 0.95)

    actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
    if severity.weight >= Severity.HIGH.weight:
        actions.append(ResponseAction.NOTIFY_SECURITY)
    if severity == Severity.CRITICAL:
        actions.append(ResponseAction.ESCALATE_SOC)
    if p.get("brute_force") and _is_public_ip(p.get("src_ip")):
        # Only a suggestion — nothing runs unless auto_response is enabled
        actions.append(ResponseAction.BLOCK_ACCESS)

    event_no = p.get("event_id_raw", "?")
    host = p.get("computer_name") or ""
    summary = f"[Windows {event_no}] {describe_windows_event(p)}" + (f" on {host}" if host else "")

    metadata = {
        "raw_payload": p,
        "source": event.source,
        "windows_event_id": event_no,
    }
    for key in ("user_id", "src_ip", "device_id"):
        val = p.get(key)
        if val and val != "unknown":
            metadata[key] = val

    return AgentFinding(
        agent_name=agent_name,
        event_id=event.event_id,
        threat_type=event.threat_type,
        severity=severity,
        confidence=round(confidence, 2),
        summary=summary,
        actions=actions,
        metadata=metadata,
    )
