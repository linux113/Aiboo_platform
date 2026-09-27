"""
core/test_event_injector.py — "Send Event" tab support.

The dashboard's Send Event tab used to POST straight from the browser to
http://localhost:8001/events. That only worked when the browser ran on the
same PC as the agent AND the agent used port 8001 (main.py uses 8000).

Now the dashboard sends the test event to the backend, the backend pushes
it over the existing agent command channel, and this handler publishes it
on the agent's event bus — so it works for any connected endpoint.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

from core.event_bus import EventBus
from core.events import Severity, ThreatEvent, ThreatType

log = logging.getLogger("TestEventInjector")

_MAX_PAYLOAD_KEYS = 30
_MAX_STR = 500


def _clean_payload(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for key, val in list(raw.items())[:_MAX_PAYLOAD_KEYS]:
        if not isinstance(key, str) or not key:
            continue
        if isinstance(val, bool) or isinstance(val, (int, float)):
            out[key[:64]] = val
        elif isinstance(val, str):
            out[key[:64]] = val[:_MAX_STR]
    return out


def build_test_event(spec: dict) -> ThreatEvent:
    """Validate the dashboard's test-event spec and build a ThreatEvent."""
    spec = spec if isinstance(spec, dict) else {}
    try:
        threat_type = ThreatType(str(spec.get("event_type") or "network_intrusion").strip().lower())
    except ValueError:
        raise RuntimeError(f"Unknown event type: {spec.get('event_type')!r}")
    try:
        severity = Severity(str(spec.get("severity") or "medium").strip().lower())
    except ValueError:
        raise RuntimeError(f"Unknown severity: {spec.get('severity')!r}")

    source = str(spec.get("source") or "dashboard-test").strip()[:64] or "dashboard-test"
    if source.startswith("windows_event_log"):
        # don't let a test masquerade as a real Windows log record
        source = f"dashboard-test:{source}"

    payload = _clean_payload(spec.get("payload"))
    payload["message"] = str(spec.get("message") or "")[:_MAX_STR]
    payload["test_event"] = True
    return ThreatEvent(source=source, threat_type=threat_type, severity=severity, payload=payload)


def make_test_event_handler(bus: EventBus) -> Callable[[str, dict], Awaitable[dict]]:
    async def inject_test_event(target: str, params: dict) -> dict:
        event = build_test_event((params or {}).get("event") or {})
        log.warning("TEST EVENT from dashboard: %s / %s (source=%s, id=%s)",
                    event.threat_type.value, event.severity.value, event.source, event.event_id)
        await bus.publish(event)
        return {"event_id": event.event_id, "threat_type": event.threat_type.value,
                "severity": event.severity.value}
    return inject_test_event
