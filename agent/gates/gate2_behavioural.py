"""
gates/gate2_behavioural.py — Gate 2: Behavioural Intelligence
 
Only processes GateDecisions where Gate 1 issued HOLD.
Performs deeper, session-aware analysis:
  - Time-of-day anomaly scoring
  - Volume and data-flow deviation from baseline
  - Cross-domain correlation (digital event + physical context)
  - Session history accumulation per entity

Now integrates MetaRiskArbiter composite risk scores to enhance decision making.
 
Gate 2 has access to a short-term session memory (per entity, 5-minute window)
so it can detect slow-burn attacks that individually look innocent.
 
Verdicts:
  PASS     → behavioural analysis clears the event
  HOLD     → still ambiguous — rare, escalates to Gate 3 with low confidence
  BLOCK    → behavioural pattern confirms threat
  ESCALATE → high confidence multi-signal threat — straight to Gate 3
"""
 
from __future__ import annotations
 
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from cachetools import TTLCache
 
from core.event_bus import EventBus
from core.events import (
    GateDecision, GateLevel, GateVerdict,
    ResponseAction, Severity, ThreatType,
    AgentFinding,
)
 
log = logging.getLogger("Gate2.Behavioural")
 
_SESSION_WINDOW_SECONDS = 300   # 5-minute entity session memory
 
# Business hours: 07:00–21:00
_BUSINESS_HOUR_START = 7
_BUSINESS_HOUR_END   = 21
 
# Data volume threshold that is suspicious even during business hours (GB)
_VOLUME_SUSPICIOUS_GB = 5.0
_VOLUME_CRITICAL_GB   = 12.0
 
# MetaRiskArbiter score thresholds (0-1000)
_META_RISK_MEDIUM = 450
_META_RISK_HIGH = 650
_META_RISK_CRITICAL = 800
 
 
class Gate2Behavioural:
    def __init__(self, bus: EventBus) -> None:
        from core.config import config
        self.bus = bus
        # entity_id → list of recent GateDecision timestamps
        self._session: dict[str, list[datetime]] = defaultdict(list)
        # MetaRiskArbiter cache: entity_id → {score (0-1), level, timestamp} (TTLCache bounded)
        self._meta_risk_cache: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=600)
 
    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._evaluate)
        # Subscribe to MetaRiskArbiter findings to keep cache updated
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        log.info("Gate 2 — Behavioural Intelligence (with MetaRiskArbiter integration) — ACTIVE")
 
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Update cache from MetaRiskArbiter findings."""
        if finding.agent_name == "MetaRiskArbiter":
            meta = finding.metadata
            entity_id = meta.get("entity_id")
            if entity_id:
                composite_score = meta.get("composite_score", 0.0)  # 0-1000
                risk_level = meta.get("risk_level", "low")
                self._meta_risk_cache[entity_id] = {
                    "score": composite_score / 1000.0,
                    "level": risk_level,
                    "timestamp": finding.timestamp,
                    "confidence": finding.confidence,
                }
 
    async def _evaluate(self, decision: GateDecision) -> None:
        # Only act on Gate 1 HOLDs — ignore everything else
        if decision.gate != GateLevel.GATE_1 or decision.verdict != GateVerdict.HOLD:
            return
 
        await asyncio.sleep(0.03)   # slightly deeper analysis
 
        entity   = self._extract_entity(decision)
        history  = self._update_session(entity, decision.timestamp)
 
        # Check if we have a meta risk score for this entity
        meta_risk = self._meta_risk_cache.get(entity)
 
        verdict, confidence, reason, actions, severity = self._score(
            decision, entity, history, meta_risk
        )
 
        new_decision = GateDecision(
            gate        = GateLevel.GATE_2,
            event_id    = decision.event_id,
            threat_type = decision.threat_type,
            severity    = severity,
            verdict     = verdict,
            confidence  = round(confidence, 2),
            reason      = reason,
            actions     = actions,
            metadata    = {
                **decision.metadata,
                "entity":         entity,
                "session_events": len(history),
                "meta_risk_score": meta_risk["score"] if meta_risk else None,
                "meta_risk_level": meta_risk["level"] if meta_risk else None,
            },
        )
 
        log.info(
            "Gate 2 [%s] entity=%s → %s (conf=%.2f) — %s",
            decision.event_id, entity, verdict.value, confidence, reason,
        )
        await self.bus.publish(new_decision)
 
    # ── Helpers ───────────────────────────────────────────────────
 
    def _extract_entity(self, d: GateDecision) -> str:
        p = d.metadata.get("payload", {})
        return (
            p.get("user_id")
            or p.get("src_ip")
            or d.metadata.get("source", "unknown")
        )
 
    def _update_session(self, entity: str, now: datetime) -> list[datetime]:
        cutoff = now - timedelta(seconds=_SESSION_WINDOW_SECONDS)
        self._session[entity] = [
            t for t in self._session[entity] if t > cutoff
        ]
        self._session[entity].append(now)
        return self._session[entity]
 
    def _score(
        self,
        d: GateDecision,
        entity: str,
        history: list[datetime],
        meta_risk: dict | None,
    ) -> tuple[GateVerdict, float, str, list[ResponseAction], Severity]:
        p        = d.metadata.get("payload", {})
        severity = d.severity
        actions  = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        confidence = d.confidence   # start from Gate 1's confidence
 
        hour = datetime.now(timezone.utc).hour
        off_hours = not (_BUSINESS_HOUR_START <= hour <= _BUSINESS_HOUR_END)
 
        # ── Apply MetaRiskArbiter signal (if available) ──
        if meta_risk:
            meta_score = meta_risk["score"]  # 0-1
            meta_level = meta_risk["level"]
            # Boost confidence based on meta score
            if meta_score > 0.7:
                confidence = min(confidence + 0.25, 1.0)
                # If meta score is critical, escalate severity
                if meta_level == "critical" and severity != Severity.CRITICAL:
                    severity = Severity.HIGH
            elif meta_score > 0.5:
                confidence = min(confidence + 0.15, 1.0)
            elif meta_score > 0.3:
                confidence = min(confidence + 0.05, 1.0)
            else:
                # Low meta risk may reduce confidence slightly
                confidence = max(0.0, confidence - 0.05)
 
        # ── Session frequency — repeated hits from same entity ────
        if len(history) >= 5:
            confidence = min(confidence + 0.20, 1.0)
            reason_prefix = f"Entity {entity!r} has {len(history)} events in 5 min"
        else:
            reason_prefix = f"Entity {entity!r}"
 
        # ── Network intrusion behaviours ──────────────────────────
        if d.threat_type == ThreatType.NETWORK_INTRUSION:
            rate = p.get("packet_rate", 0)
            sig  = p.get("signature", "")
 
            if off_hours and rate > 1000:
                confidence = min(confidence + 0.15, 1.0)
                reason = f"{reason_prefix} — off-hours high-rate traffic ({rate}/s)"
                actions += [ResponseAction.ISOLATE_ASSET, ResponseAction.PSEUDO_LOCK]
                severity = Severity.HIGH
                # If meta risk also high, escalate
                if meta_risk and meta_risk["score"] > 0.6:
                    severity = Severity.CRITICAL
                    actions.append(ResponseAction.ESCALATE_SOC)
                    return GateVerdict.ESCALATE, confidence, reason, actions, severity
                return GateVerdict.BLOCK, confidence, reason, actions, severity
 
            if len(history) >= 3:
                reason = f"{reason_prefix} — repeated network probes, likely scan"
                actions.append(ResponseAction.ISOLATE_ASSET)
                if meta_risk and meta_risk["score"] > 0.5:
                    actions.append(ResponseAction.ESCALATE_SOC)
                    return GateVerdict.ESCALATE, confidence, reason, actions, severity
                return GateVerdict.BLOCK, confidence, reason, actions, severity
 
            # If meta risk is high, even if traffic looks normal, we may block
            if meta_risk and meta_risk["score"] > 0.7:
                actions.append(ResponseAction.ISOLATE_ASSET)
                return GateVerdict.BLOCK, confidence, \
                       f"{reason_prefix} — meta risk high, network anomaly suspected", \
                       actions, Severity.HIGH
 
            return GateVerdict.PASS, 0.30, \
                   f"{reason_prefix} — traffic pattern within behavioural norms", \
                   actions, severity
 
        # ── Identity mismatch behaviours ──────────────────────────
        if d.threat_type == ThreatType.IDENTITY_MISMATCH:
            bio     = float(p.get("biometric_score", 1.0))
            claimed = p.get("claimed_location", "")
            detected= p.get("detected_location", "")
            mismatch= claimed and detected and claimed != detected
 
            if mismatch and off_hours:
                confidence = min(confidence + 0.20, 1.0)
                severity   = Severity.CRITICAL
                actions   += [ResponseAction.REVOKE_IDENTITY, ResponseAction.PSEUDO_LOCK,
                              ResponseAction.NOTIFY_SECURITY]
                if meta_risk and meta_risk["score"] > 0.5:
                    actions.append(ResponseAction.ESCALATE_SOC)
                reason = (f"{reason_prefix} — location mismatch + off-hours "
                          f"({claimed!r} vs {detected!r})")
                return GateVerdict.ESCALATE, confidence, reason, actions, severity
 
            if mismatch:
                confidence = min(confidence + 0.10, 1.0)
                actions.append(ResponseAction.REVOKE_IDENTITY)
                if meta_risk and meta_risk["score"] > 0.6:
                    actions.append(ResponseAction.ESCALATE_SOC)
                    return GateVerdict.ESCALATE, confidence, reason, actions, severity
                reason = f"{reason_prefix} — location mismatch confirmed at Gate 2"
                return GateVerdict.BLOCK, confidence, reason, actions, severity
 
            # Even without mismatch, if meta risk is critical, we treat as suspicious
            if meta_risk and meta_risk["score"] > 0.8:
                actions.append(ResponseAction.STEP_UP_AUTH)
                actions.append(ResponseAction.CHALLENGE_MFA)
                return GateVerdict.BLOCK, confidence, \
                       f"{reason_prefix} — meta risk critical, additional verification required", \
                       actions, Severity.HIGH
 
            return GateVerdict.PASS, 0.30, \
                   f"{reason_prefix} — identity behavioural profile acceptable", \
                   actions, severity
 
        # ── Physical intrusion behaviours ─────────────────────────
        if d.threat_type == ThreatType.PHYSICAL_INTRUSION:
            motion = float(p.get("motion_anomaly_score", 0))
            zone   = p.get("zone", "")
 
            if motion > 0.85 and off_hours:
                confidence = min(confidence + 0.25, 1.0)
                severity   = Severity.CRITICAL
                actions   += [ResponseAction.LOCK_ZONE, ResponseAction.NOTIFY_SECURITY,
                              ResponseAction.ESCALATE_SOC]
                if meta_risk and meta_risk["score"] > 0.5:
                    actions.append(ResponseAction.ISOLATE_ASSET)
                reason = (f"{reason_prefix} — high motion anomaly ({motion:.2f}) "
                          f"in {zone!r} outside business hours")
                return GateVerdict.ESCALATE, confidence, reason, actions, severity
 
            if motion > 0.70:
                confidence = min(confidence + 0.15, 1.0)
                actions.append(ResponseAction.LOCK_ZONE)
                if meta_risk and meta_risk["score"] > 0.6:
                    actions.append(ResponseAction.ESCALATE_SOC)
                    return GateVerdict.ESCALATE, confidence, reason, actions, severity
                reason = f"{reason_prefix} — motion anomaly {motion:.2f} in {zone!r}"
                return GateVerdict.BLOCK, confidence, reason, actions, severity
 
            return GateVerdict.PASS, 0.30, \
                   f"{reason_prefix} — physical behaviour within norms", \
                   actions, severity
 
        # ── Insider threat behaviours ─────────────────────────────
        vol = float(p.get("unusual_data_volume_gb", 0))
        dst = p.get("destination", "")
 
        if vol >= _VOLUME_CRITICAL_GB or (off_hours and vol >= _VOLUME_SUSPICIOUS_GB):
            confidence = min(confidence + 0.25, 1.0)
            severity   = Severity.CRITICAL
            actions   += [ResponseAction.REVOKE_IDENTITY, ResponseAction.ISOLATE_ASSET,
                          ResponseAction.ESCALATE_SOC]
            if meta_risk and meta_risk["score"] > 0.5:
                actions.append(ResponseAction.PSEUDO_LOCK)
            reason = (f"{reason_prefix} — {vol}GB to {dst!r} "
                      f"{'(off-hours)' if off_hours else ''}")
            return GateVerdict.ESCALATE, confidence, reason, actions, severity
 
        if vol >= _VOLUME_SUSPICIOUS_GB:
            confidence = min(confidence + 0.15, 1.0)
            actions.append(ResponseAction.REVOKE_IDENTITY)
            if meta_risk and meta_risk["score"] > 0.6:
                actions.append(ResponseAction.ESCALATE_SOC)
                return GateVerdict.ESCALATE, confidence, reason, actions, severity
            reason = f"{reason_prefix} — suspicious data volume {vol}GB to {dst!r}"
            return GateVerdict.BLOCK, confidence, reason, actions, severity
 
        # If meta risk is high but no other signals, we may still block or escalate
        if meta_risk and meta_risk["score"] > 0.8:
            actions.append(ResponseAction.REVOKE_IDENTITY)
            actions.append(ResponseAction.NOTIFY_SECURITY)
            return GateVerdict.BLOCK, confidence, \
                   f"{reason_prefix} — meta risk critical, proactive containment", \
                   actions, Severity.HIGH
 
        return GateVerdict.PASS, 0.35, \
               f"{reason_prefix} — insider behaviour within baseline", \
               actions, severity