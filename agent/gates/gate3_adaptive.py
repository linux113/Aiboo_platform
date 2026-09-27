"""
gates/gate3_adaptive.py — Gate 3: Adaptive Response
 
The final gate. Receives GateDecisions where:
  - Gate 1 issued BLOCK or ESCALATE
  - Gate 2 issued BLOCK or ESCALATE
 
Gate 3 does NOT re-analyse the threat — that work is done.
Its job is to:
  1. Choose the *optimal* response strategy based on all available context
  2. Apply Pseudo-Lock with precision (right endpoint, right decoy type)
  3. Adapt its own response thresholds based on the attack pattern seen so far
  4. Issue the final GateDecision with full action set
  5. Feed the threat fingerprint back into a live adaptation registry so
     future Gate 1 / Gate 2 evaluations are sharper
 
This is the "learning" gate — it makes AiBoO's tri-gate structure
self-improving rather than static.
"""
 
from __future__ import annotations
 
import asyncio
import logging
import random
import string
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cachetools import TTLCache
 
from core.event_bus import EventBus
from core.config import config
from core.events import (
    GateDecision, GateLevel, GateVerdict,
    ResponseAction, Severity, ThreatType,
)
 
log = logging.getLogger("Gate3.Adaptive")
 
 
@dataclass
class ThreatFingerprint:
    """
    Compact record of a confirmed threat. Gate 3 builds this registry
    and shares it back to Gate 1 so known patterns are caught faster
    on the next encounter.
    """
    threat_type: ThreatType
    severity:    Severity
    entity:      str
    actions:     list[ResponseAction]
    gate_path:   str                   # e.g. "G1:BLOCK" or "G1:HOLD→G2:ESCALATE"
    seen_at:     datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    occurrences: int = 1
 
 
def _decoy_endpoint(entity: str) -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    port  = random.randint(32768, 60999)
    return f"decoy-{token}.aiboo.internal:{port}"
 
 
class Gate3Adaptive:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        # Threat fingerprint registry — TTLCache bounded
        self._registry: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400 * 7)
        # Adaptation counters — if same entity hits Gate 3 repeatedly,
        # automatically elevate their baseline threat level
        self._repeat_hits: dict[str, int] = defaultdict(int)
 
    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._evaluate)
        log.info("Gate 3 — Adaptive Response — ACTIVE")
 
    async def _evaluate(self, decision: GateDecision) -> None:
        # Gate 3 only activates on BLOCK or ESCALATE from Gate 1 or 2
        if decision.verdict not in (GateVerdict.BLOCK, GateVerdict.ESCALATE):
            return
        if decision.gate not in (GateLevel.GATE_1, GateLevel.GATE_2):
            return
 
        await asyncio.sleep(0.02)
 
        entity    = self._extract_entity(decision)
        gate_path = self._gate_path_label(decision)
        self._repeat_hits[entity] += 1
        repeat    = self._repeat_hits[entity]
 
        # Build optimal action set
        actions = list(dict.fromkeys(decision.actions))   # preserve order, dedupe
 
        # Always include Pseudo-Lock at Gate 3
        if ResponseAction.PSEUDO_LOCK not in actions:
            actions.append(ResponseAction.PSEUDO_LOCK)
 
        # Repeat offender — escalate harder
        if repeat >= 3:
            for a in [ResponseAction.ESCALATE_SOC, ResponseAction.NOTIFY_SECURITY,
                      ResponseAction.ISOLATE_ASSET]:
                if a not in actions:
                    actions.append(a)
 
        severity = decision.severity
        if repeat >= 3 and severity != Severity.CRITICAL:
            severity = Severity.CRITICAL
            log.warning(
                "Entity %r has triggered Gate 3 %d times — severity elevated to CRITICAL",
                entity, repeat,
            )
 
        # Pseudo-Lock detail
        decoy  = _decoy_endpoint(entity)
        reason = (
            f"Gate 3 adaptive response for {entity!r} "
            f"(path={gate_path}, repeat={repeat}). "
            f"Pseudo-Lock → {decoy}. "
            f"{decision.reason}"
        )
 
        final = GateDecision(
            gate        = GateLevel.GATE_3,
            event_id    = decision.event_id,
            threat_type = decision.threat_type,
            severity    = severity,
            verdict     = GateVerdict.BLOCK,
            confidence  = min(decision.confidence + 0.05, 1.0),
            reason      = reason,
            actions     = actions,
            metadata    = {
                **decision.metadata,
                "entity":     entity,
                "decoy":      decoy,
                "gate_path":  gate_path,
                "repeat":     repeat,
            },
        )
 
        log.critical(
            "Gate 3 [%s] FINAL — entity=%r path=%s repeat=%d sev=%s conf=%.2f",
            decision.event_id, entity, gate_path, repeat,
            severity.value, final.confidence,
        )
 
        # Update fingerprint registry — feeds back to Gate 1 learning
        self._fingerprint(decision, entity, gate_path, actions, severity)
 
        await self.bus.publish(final)
 
    # ── Helpers ───────────────────────────────────────────────────
 
    def _extract_entity(self, d: GateDecision) -> str:
        p = d.metadata.get("payload", {})
        return (
            p.get("user_id")
            or p.get("src_ip")
            or d.metadata.get("source", "unknown")
        )
 
    def _gate_path_label(self, d: GateDecision) -> str:
        return f"G{d.gate.value}:{d.verdict.value.upper()}"
 
    def _fingerprint(
        self,
        d: GateDecision,
        entity: str,
        gate_path: str,
        actions: list[ResponseAction],
        severity: Severity,
    ) -> None:
        key = f"{d.threat_type.value}:{entity}"
        if key in self._registry:
            self._registry[key].occurrences += 1
            self._registry[key].severity = severity
            log.info(
                "Fingerprint updated — %s occurrences=%d",
                key, self._registry[key].occurrences,
            )
        else:
            self._registry[key] = ThreatFingerprint(
                threat_type = d.threat_type,
                severity    = severity,
                entity      = entity,
                actions     = actions,
                gate_path   = gate_path,
            )
            log.info("New fingerprint registered — %s", key)
 
    def known_entities(self) -> list[ThreatFingerprint]:
        """Expose the registry for Gate 1 to query during startup."""
        return list(self._registry.values())
 
    def repeat_count(self, entity: str) -> int:
        return self._repeat_hits.get(entity, 0)