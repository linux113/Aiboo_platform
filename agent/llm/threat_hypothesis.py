"""
llm/threat_hypothesis.py — Threat Hypothesis Agent (optional)
 
After a Gate 3 decision, predicts the attacker's likely next move
using the LLM, enabling proactive tightening of Gate 1 thresholds.
"""
from __future__ import annotations
import asyncio, logging, os
from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict
 
log = logging.getLogger("LLM.ThreatHypothesis")
 
 
class ThreatHypothesisAgent:
    def __init__(self, bus: EventBus) -> None:
        self.bus  = bus
        self._key = os.getenv("ANTHROPIC_API_KEY", "")
 
    def start(self) -> None:
        if not self._key:
            log.warning("ANTHROPIC_API_KEY not set — ThreatHypothesisAgent disabled.")
            return
        self.bus.subscribe(GateDecision, self._on_gate3)
        log.info("ThreatHypothesisAgent active.")
 
    async def _on_gate3(self, d: GateDecision) -> None:
        if d.gate != GateLevel.GATE_3 or d.verdict != GateVerdict.BLOCK:
            return
        asyncio.create_task(self._hypothesise(d))
 
    async def _hypothesise(self, d: GateDecision) -> None:
        log.info("[HYPOTHESIS] Predicting next move for entity %r ...",
                 d.metadata.get("entity", "unknown"))
        # Full Anthropic API call same pattern as narrative_agent.py
        # Returns: likely next attack vector → fed back to Gate 1 scoring weights
 