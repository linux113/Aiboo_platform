"""
llm/threat_hypothesis.py — Threat Hypothesis Agent

After a Gate 3 BLOCK decision, predicts the attacker's likely next move
using the LLM (Anthropic). Falls back to a rule-based predictor when no
API key is configured. Hypotheses are stored in the shared InsightStore
and served to the dashboard via GET /llm/insights.
"""
from __future__ import annotations

import asyncio
import logging

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict
from .advisor import call_llm, heuristic_advice, insights, llm_available

log = logging.getLogger("LLM.ThreatHypothesis")

_SYSTEM = (
    "You are AiBoO's threat-hypothesis engine. Given a confirmed attack "
    "(Gate 3 BLOCK), predict the attacker's most likely NEXT move in 2-3 "
    "short sentences and the single best pre-emptive containment. "
    "Be concrete and tactical. No preamble."
)

# Offline fallback: what typically comes after each threat type
_NEXT_MOVE: dict[str, str] = {
    "network_intrusion": (
        "Likely next move: lateral movement via SMB/RDP from the compromised host, "
        "followed by credential dumping. Pre-emptively: microsegment the host and "
        "revoke cached domain credentials."
    ),
    "physical_intrusion": (
        "Likely next move: attempted access to adjacent restricted zones using the "
        "same badge/tailgate method. Pre-emptively: lock adjacent zones and raise "
        "camera sensitivity in the corridor."
    ),
    "identity_mismatch": (
        "Likely next move: privilege escalation or mailbox rule abuse with the "
        "hijacked identity. Pre-emptively: revoke sessions and rotate credentials."
    ),
    "insider_threat": (
        "Likely next move: bulk exfiltration to external storage outside business "
        "hours. Pre-emptively: throttle outbound transfers and watch removable media."
    ),
    "memory_threat": (
        "Likely next move: ransomware payload staging and shadow-copy deletion. "
        "Pre-emptively: isolate the host and snapshot volatile memory for forensics."
    ),
}


class ThreatHypothesisAgent:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._ready = llm_available()

    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._on_gate3)
        if not self._ready:
            log.warning("ANTHROPIC_API_KEY not set — ThreatHypothesisAgent running in OFFLINE rule-based mode.")
        else:
            log.info("ThreatHypothesisAgent active (LLM: %s).", "enabled" if self._ready else "offline")

    async def stop(self) -> None:
        pass  # no long-lived resources

    async def _on_gate3(self, d: GateDecision) -> None:
        if d.gate != GateLevel.GATE_3 or d.verdict != GateVerdict.BLOCK:
            return
        asyncio.create_task(self._hypothesise(d))

    async def _hypothesise(self, d: GateDecision) -> None:
        entity = str(d.metadata.get("entity", d.metadata.get("src_ip", "unknown")))
        log.info("[HYPOTHESIS] Predicting next move for entity %r (event %s)", entity, d.event_id)

        user = (
            f"Threat type: {d.threat_type.value}\n"
            f"Severity: {d.severity.value}\n"
            f"Confidence: {d.confidence:.0%}\n"
            f"Entity: {entity}\n"
            f"Reason for block: {d.reason}\n"
            f"Metadata: { {k: v for k, v in list(d.metadata.items())[:8]} }"
        )

        text = None
        if self._ready:
            text = await call_llm(_SYSTEM, user, max_tokens=300)

        source = "llm"
        if not text:
            source = "offline-rules"
            text = _NEXT_MOVE.get(
                d.threat_type.value,
                "Likely next move: continued reconnaissance of the same vector. "
                "Pre-emptively: tighten Gate 1 thresholds for this entity and "
                "increase monitoring retention.",
            )

        insights.add_hypothesis(d.event_id, text, entity, source=source)
        log.info("[HYPOTHESIS] %s → %s", entity, text)
