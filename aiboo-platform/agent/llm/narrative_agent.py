"""
llm/narrative_agent.py — LLM Narrative Agent (optional)

Subscribes to CorrelatedAlert and generates a plain-English
incident report. Uses the shared Anthropic helper (llm.advisor);
falls back to a templated offline report when no API key is set.
Reports are stored in the shared InsightStore and served via
GET /llm/insights.
"""
from __future__ import annotations

import asyncio
import logging

from core.event_bus import EventBus
from core.events import CorrelatedAlert, ResponseAction
from .advisor import call_llm, insights, llm_available

log = logging.getLogger("LLM.NarrativeAgent")

_SYSTEM = (
    "You are AiBoO's security narrative engine. "
    "Write a concise, plain-English incident report "
    "for a SOC analyst. Include: what happened, "
    "which systems are affected, what actions were taken, "
    "and the recommended next step."
)


def _offline_report(alert: CorrelatedAlert) -> str:
    actions = ", ".join(a.value for a in alert.actions) or "none yet"
    findings = "; ".join(f.summary for f in alert.findings[:5]) or alert.description
    return (
        f"INCIDENT {alert.alert_id} — {alert.threat_type.value.replace('_', ' ').title()} "
        f"({alert.severity.value.upper()}, confidence {alert.confidence:.0%}).\n"
        f"What happened: {findings}\n"
        f"Actions taken/applied: {actions}.\n"
        f"Recommended next step: verify containment on the affected assets, "
        f"review related findings in the Agent Console, and escalate to the SOC "
        f"if activity persists after isolation."
    )


class NarrativeAgent:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._ready = llm_available()
        self._generating: set[str] = set()

    def start(self) -> None:
        self.bus.subscribe(CorrelatedAlert, self._on_alert)
        if not self._ready:
            log.warning("ANTHROPIC_API_KEY not set — NarrativeAgent running in OFFLINE templated mode.")
        else:
            log.info("NarrativeAgent active — will generate incident reports.")

    async def stop(self) -> None:
        pass  # no long-lived resources (httpx client is per-call now)

    async def _on_alert(self, alert: CorrelatedAlert) -> None:
        if alert.alert_id in self._generating:
            return
        self._generating.add(alert.alert_id)
        asyncio.create_task(self._generate(alert))

    async def _generate(self, alert: CorrelatedAlert) -> None:
        try:
            user = (
                f"Alert: {alert.description}\n"
                f"Severity: {alert.severity.value}\n"
                f"Confidence: {alert.confidence:.0%}\n"
                f"Findings: {[f.summary for f in alert.findings]}\n"
                f"Actions taken: {[a.value for a in alert.actions]}"
            )
            narrative = None
            if self._ready:
                narrative = await call_llm(_SYSTEM, user, max_tokens=500)
            if not narrative:
                narrative = _offline_report(alert)
            insights.add_report(alert.alert_id, narrative,
                                source="llm" if self._ready else "offline-template")
            log.info("Narrative for alert %s:\n%s", alert.alert_id, narrative)
        except Exception as e:
            log.error("Narrative generation failed: %s", e)
        finally:
            self._generating.discard(alert.alert_id)
