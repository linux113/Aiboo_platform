"""
engines/meta_risk_arbiter.py — Meta‑Risk Arbiter (Master ML Layer)

Collects scores from all specialized engines:
- UEBA Engine (behavioral deviations)
- Threat Intelligence Engine (IOC matches, dark web)
- Physical Security Engine (physical-cyber correlation)
- Insider Threat Engine (insider risk)
- Device Trust Engine (device health/fingerprint)
- Risk Scoring Engine (general risk factors)

Applies:
- Multi-signal confirmation: requires at least 3 independent signals
  to escalate above MEDIUM risk
- Adversarial 'skeptic' model to reduce false positives
- Dynamic weighting of dimensions
- Temporal decay of risk

Publishes AgentFinding with Composite Risk Score (0-1000) and risk level.

Part of Layer 2: Detection & Intelligence.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Set, Tuple, Any

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity, AgentFinding,
    AccessRequest, RiskLevel, ResponseAction
)

log = logging.getLogger("MetaRiskArbiter")

# ============================================
# Configuration Constants
# ============================================

# Dimension weights (sum to 1.0)
DEFAULT_DIMENSION_WEIGHTS = {
    "behavioral": 0.20,      # from UEBA
    "threat_intel": 0.20,    # from Threat Intelligence
    "physical": 0.15,        # from Physical Security
    "insider": 0.15,         # from Insider Threat Engine
    "device": 0.15,          # from Device Trust Engine
    "network": 0.15,         # from general risk scoring (network/identity)
}

# Risk thresholds (0-1000 scale)
RISK_THRESHOLDS = {
    RiskLevel.LOW: 200,
    RiskLevel.MEDIUM: 450,
    RiskLevel.HIGH: 650,
    RiskLevel.CRITICAL: 800,
}

# Minimum number of corroborating signals to escalate above MEDIUM
MIN_CORROBORATING_SIGNALS = 3

# Skeptic model threshold: if skeptic score > 0.5, reduce risk
SKEPTIC_THRESHOLD = 0.5

# Time decay: risk decays by this fraction per hour
DECAY_RATE_PER_HOUR = 0.01  # 1% per hour

# Minimum time between alerts per entity (cooldown)
ALERT_COOLDOWN_SECONDS = 600  # 10 minutes

# Signal age window (seconds) for considering signals as "corroborating"
CORROBORATION_WINDOW = 300  # 5 minutes


@dataclass
class EntityRiskState:
    """Risk state for a single entity (user, device, IP)."""
    entity_id: str
    entity_type: str  # "user", "device", "ip"

    # Dimension scores (0-1)
    dimension_scores: Dict[str, float] = field(default_factory=dict)

    # Combined risk score (0-1000)
    composite_score: float = 0.0

    # Risk level from thresholds
    risk_level: RiskLevel = RiskLevel.LOW

    # Signal history (for corroboration and skeptic model)
    recent_signals: List[Dict[str, Any]] = field(default_factory=list)
    max_signal_history: int = 50

    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_decay: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_alert: Optional[datetime] = None

    # Counters
    signal_count: int = 0
    high_severity_count: int = 0

    def update_dimension(self, dim: str, score: float):
        """Update a dimension score (0-1)."""
        self.dimension_scores[dim] = min(1.0, max(0.0, score))
        self.last_updated = datetime.now(timezone.utc)
        self._recalculate()

    def add_signal(self, signal: Dict[str, Any]):
        """Add a signal for corroboration and skeptic model."""
        self.recent_signals.append(signal)
        if len(self.recent_signals) > self.max_signal_history:
            self.recent_signals = self.recent_signals[-self.max_signal_history:]
        self.signal_count += 1
        self.last_updated = datetime.now(timezone.utc)

    def _recalculate(self):
        """Recalculate composite score from dimension scores."""
        total_weighted = 0.0
        total_weight = 0.0
        for dim, weight in DEFAULT_DIMENSION_WEIGHTS.items():
            score = self.dimension_scores.get(dim, 0.0)
            total_weighted += score * weight
            total_weight += weight
        if total_weight > 0:
            raw_score = total_weighted / total_weight
        else:
            raw_score = 0.0
        self.composite_score = raw_score * 1000
        self.risk_level = self._score_to_risk_level(self.composite_score)
        self.last_updated = datetime.now(timezone.utc)

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert composite score to RiskLevel."""
        if score >= RISK_THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def apply_decay(self, hours: float):
        """Apply time decay to all dimension scores."""
        decay_factor = 1 - (DECAY_RATE_PER_HOUR * hours)
        if decay_factor < 0:
            decay_factor = 0
        for dim in list(self.dimension_scores.keys()):
            self.dimension_scores[dim] *= decay_factor
        self.last_decay = datetime.now(timezone.utc)
        self._recalculate()


class MetaRiskArbiter:
    """
    Meta-Risk Arbiter — master ML layer.
    Aggregates signals from all engines, applies multi-signal confirmation,
    skeptic model, and produces final Composite Risk Score.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._states: Dict[str, EntityRiskState] = {}
        self._running = False

        # Background tasks
        self._decay_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None

        # Configuration (can be externally updated)
        self._config = {
            "dimension_weights": DEFAULT_DIMENSION_WEIGHTS.copy(),
            "risk_thresholds": RISK_THRESHOLDS.copy(),
            "min_corroborating_signals": MIN_CORROBORATING_SIGNALS,
            "skeptic_threshold": SKEPTIC_THRESHOLD,
            "decay_rate_per_hour": DECAY_RATE_PER_HOUR,
            "alert_cooldown_seconds": ALERT_COOLDOWN_SECONDS,
            "corroboration_window_seconds": CORROBORATION_WINDOW,
        }

        # Track previous alerts for cooldown
        self._last_alert_time: Dict[str, datetime] = {}

        log.info("MetaRiskArbiter initialized")

    def start(self) -> None:
        """Start the arbiter: subscribe to events and start background tasks."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._decay_task = asyncio.create_task(self._decay_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("MetaRiskArbiter started — synthesizing risk intelligence")

    # ============================================
    # Event Handlers
    # ============================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events to extract signals."""
        p = event.payload
        entity_id = self._extract_entity_id(p)
        if not entity_id:
            return

        state = self._get_or_create_state(entity_id, self._infer_entity_type(p))

        # Extract dimension scores based on threat type
        dimension_updates = self._extract_dimension_scores(event)
        for dim, score in dimension_updates.items():
            if score > 0:
                state.update_dimension(dim, score)

        # Add signal for corroboration
        signal = {
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "threat_type": event.threat_type.value,
            "severity": event.severity.value,
            "payload": p,
            "dimension": list(dimension_updates.keys())[0] if dimension_updates else "unknown",
            "score": list(dimension_updates.values())[0] if dimension_updates else 0.0,
        }
        state.add_signal(signal)

        # Re-evaluate and potentially alert
        await self._evaluate_and_alert(state, event)

    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests (low-level signal)."""
        user_id = request.user_id
        if not user_id:
            return

        state = self._get_or_create_state(user_id, "user")

        # Access requests can have some risk if unusual (handled by other engines)
        # We'll add a minor signal for behavioral dimension
        # Only if there's a risk score from the request itself
        if request.risk_score > 0.3:
            state.update_dimension("behavioral", request.risk_score * 0.3)

        signal = {
            "timestamp": request.timestamp.isoformat(),
            "source": "AccessRequest",
            "resource": request.resource,
            "location": request.location,
            "network": request.network,
        }
        state.add_signal(signal)

        await self._evaluate_and_alert(state, None)

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings (high-confidence signals)."""
        p = finding.metadata
        entity_id = p.get("user_id") or p.get("src_ip") or p.get("device_id")
        if not entity_id:
            return

        state = self._get_or_create_state(entity_id, self._infer_entity_type_from_finding(finding))

        # Agent findings can directly influence multiple dimensions
        if finding.severity == Severity.CRITICAL and finding.confidence > 0.8:
            # Strong signal: boost relevant dimensions
            if "network" in finding.agent_name.lower():
                state.update_dimension("network", min(1.0, state.dimension_scores.get("network", 0.0) + 0.4))
            elif "identity" in finding.agent_name.lower():
                state.update_dimension("behavioral", min(1.0, state.dimension_scores.get("behavioral", 0.0) + 0.3))
            elif "insider" in finding.agent_name.lower():
                state.update_dimension("insider", min(1.0, state.dimension_scores.get("insider", 0.0) + 0.4))
            else:
                # Generic boost
                state.update_dimension("threat_intel", min(1.0, state.dimension_scores.get("threat_intel", 0.0) + 0.3))

        signal = {
            "timestamp": finding.timestamp.isoformat(),
            "source": finding.agent_name,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "summary": finding.summary,
        }
        state.add_signal(signal)

        await self._evaluate_and_alert(state, None)

    # ============================================
    # Core Evaluation & Alerting
    # ============================================

    async def _evaluate_and_alert(self, state: EntityRiskState, original_event: Optional[ThreatEvent]) -> None:
        """
        Evaluate current risk, apply skeptic and corroboration, and alert if needed.
        """
        # 1. Apply multi-signal corroboration
        corroborated_risk = self._apply_corroboration(state)

        # 2. Apply skeptic model
        final_risk = self._apply_skeptic(state, corroborated_risk)

        # Update state with final scores
        state.composite_score = final_risk
        state.risk_level = state._score_to_risk_level(final_risk)

        # 3. Check if alert is needed (medium or higher)
        if state.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            # Cooldown check
            now = datetime.now(timezone.utc)
            last = self._last_alert_time.get(state.entity_id)
            if last and (now - last).total_seconds() < self._config["alert_cooldown_seconds"]:
                return

            # Publish alert
            await self._publish_risk_alert(state, original_event)
            self._last_alert_time[state.entity_id] = now

    def _apply_corroboration(self, state: EntityRiskState) -> float:
        """
        Apply multi-signal confirmation: require at least N distinct dimensions
        to have non-zero signals within the corroboration window.
        If fewer, reduce the composite score.
        """
        # Count active dimensions with scores > 0.1 in recent signals
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._config["corroboration_window_seconds"])

        active_dimensions = set()
        for signal in state.recent_signals:
            if "timestamp" in signal:
                try:
                    sig_time = datetime.fromisoformat(signal["timestamp"])
                    if sig_time >= cutoff:
                        dim = signal.get("dimension")
                        if dim:
                            active_dimensions.add(dim)
                except:
                    pass

        # Also include dimension scores directly if they exceed threshold
        for dim, score in state.dimension_scores.items():
            if score > 0.15:  # non-trivial
                active_dimensions.add(dim)

        min_signals = self._config["min_corroborating_signals"]
        if len(active_dimensions) < min_signals:
            # Penalize: reduce score by factor proportional to missing signals
            missing = min_signals - len(active_dimensions)
            penalty_factor = max(0.2, 1.0 - (missing * 0.25))
            reduced_score = state.composite_score * penalty_factor
            log.debug(f"Corroboration: {len(active_dimensions)} active dims, reducing from {state.composite_score:.1f} to {reduced_score:.1f}")
            return reduced_score

        return state.composite_score

    def _apply_skeptic(self, state: EntityRiskState, raw_score: float) -> float:
        """
        Simulate a skeptic model: if the state has many signals with low confidence,
        or if there are inconsistent signals, reduce risk.
        """
        # Use a simple heuristic: if average signal confidence is low, reduce.
        # For each signal, we might have a confidence (if available).
        avg_confidence = 0.0
        count = 0
        for signal in state.recent_signals[-10:]:  # last 10 signals
            conf = signal.get("confidence")
            if conf is not None:
                avg_confidence += conf
                count += 1
        if count > 0:
            avg_confidence /= count
        else:
            avg_confidence = 0.5  # default

        # If average confidence is below threshold, reduce score
        if avg_confidence < self._config["skeptic_threshold"]:
            reduction = (self._config["skeptic_threshold"] - avg_confidence) * 0.3
            adjusted = raw_score * (1 - reduction)
            log.debug(f"Skeptic: avg_confidence={avg_confidence:.2f}, reducing from {raw_score:.1f} to {adjusted:.1f}")
            return adjusted

        return raw_score

    async def _publish_risk_alert(self, state: EntityRiskState, original_event: Optional[ThreatEvent]) -> None:
        """Publish an AgentFinding with the final risk assessment."""
        # Map risk level to severity
        severity_map = {
            RiskLevel.LOW: Severity.LOW,
            RiskLevel.MEDIUM: Severity.MEDIUM,
            RiskLevel.HIGH: Severity.HIGH,
            RiskLevel.CRITICAL: Severity.CRITICAL,
        }
        severity = severity_map.get(state.risk_level, Severity.MEDIUM)

        # Build actions based on risk level
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        if state.risk_level == RiskLevel.HIGH:
            actions.append(ResponseAction.NOTIFY_SECURITY)
        elif state.risk_level == RiskLevel.CRITICAL:
            actions.extend([ResponseAction.ISOLATE_ASSET, ResponseAction.ESCALATE_SOC, ResponseAction.PSEUDO_LOCK])

        # Also escalate if insider or threat intel dimensions are high
        if state.dimension_scores.get("insider", 0.0) > 0.6:
            if ResponseAction.REVOKE_IDENTITY not in actions:
                actions.append(ResponseAction.REVOKE_IDENTITY)
        if state.dimension_scores.get("threat_intel", 0.0) > 0.7:
            if ResponseAction.BLOCK_ACCESS not in actions:
                actions.append(ResponseAction.BLOCK_ACCESS)

        finding = AgentFinding(
            agent_name="MetaRiskArbiter",
            event_id=original_event.event_id if original_event else "unknown",
            threat_type=ThreatType.CORRELATED_ATTACK,  # Use correlated as it's a synthesis
            severity=severity,
            confidence=min(1.0, state.composite_score / 1000),
            summary=(
                f"Composite Risk Score: {state.composite_score:.1f}/1000 (Risk Level: {state.risk_level.value}). "
                f"Entity: {state.entity_id} ({state.entity_type}). "
                f"Dimensions: {', '.join(f'{k}={v:.2f}' for k, v in state.dimension_scores.items() if v > 0.1)}"
            ),
            actions=actions,
            metadata={
                "entity_id": state.entity_id,
                "entity_type": state.entity_type,
                "composite_score": state.composite_score,
                "risk_level": state.risk_level.value,
                "dimension_scores": state.dimension_scores,
                "signal_count": state.signal_count,
                "corroborating_signals": len([s for s in state.recent_signals if s.get("dimension")]),
                "recent_signals": state.recent_signals[-5:],  # last 5 for context
            }
        )

        await self.bus.publish(finding)
        log.info(
            f"Risk alert: {state.entity_id} score={state.composite_score:.1f} level={state.risk_level.value} "
            f"dims={state.dimension_scores}"
        )

    # ============================================
    # State Management & Utilities
    # ============================================

    def _get_or_create_state(self, entity_id: str, entity_type: str) -> EntityRiskState:
        """Get existing state or create a new one."""
        if entity_id in self._states:
            return self._states[entity_id]

        state = EntityRiskState(entity_id=entity_id, entity_type=entity_type)
        self._states[entity_id] = state
        log.debug(f"Created risk state for {entity_type}: {entity_id}")
        return state

    def _extract_entity_id(self, payload: Dict) -> Optional[str]:
        """Extract primary entity ID from payload."""
        for key in ["user_id", "src_ip", "device_id", "entity_id"]:
            if payload.get(key):
                return str(payload[key])
        return None

    def _infer_entity_type(self, payload: Dict) -> str:
        """Infer entity type from payload fields."""
        if payload.get("user_id"):
            return "user"
        if payload.get("src_ip"):
            return "ip"
        if payload.get("device_id"):
            return "device"
        return "unknown"

    def _infer_entity_type_from_finding(self, finding: AgentFinding) -> str:
        """Infer entity type from finding metadata."""
        if finding.metadata.get("user_id"):
            return "user"
        if finding.metadata.get("src_ip"):
            return "ip"
        if finding.metadata.get("device_id"):
            return "device"
        return "unknown"

    def _extract_dimension_scores(self, event: ThreatEvent) -> Dict[str, float]:
        """
        Extract dimension scores from a ThreatEvent.
        Returns a dict of dimension -> score (0-1).
        """
        p = event.payload
        scores = {}

        # Based on threat type
        if event.threat_type == ThreatType.ANOMALOUS_BEHAVIOR:
            scores["behavioral"] = p.get("overall_anomaly_score", 0.0)
        elif event.threat_type == ThreatType.THREAT_INTEL_ALERT:
            scores["threat_intel"] = p.get("avg_confidence", 0.0)
        elif event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            scores["physical"] = 0.5  # base, can be refined
        elif event.threat_type == ThreatType.INSIDER_THREAT:
            scores["insider"] = p.get("overall_score", 0.0) / 1000 if p.get("overall_score") else 0.3
        elif event.threat_type == ThreatType.NETWORK_INTRUSION:
            scores["network"] = event.severity.weight / 4  # normalize
        elif event.threat_type == ThreatType.IDENTITY_MISMATCH:
            scores["behavioral"] = 0.4  # identity issues affect behavioral
        elif event.threat_type == ThreatType.DEVICE_HEALTH_FAIL:
            scores["device"] = 0.6

        # If payload has explicit dimension scores, use them
        if "dimension_scores" in p:
            for dim, score in p["dimension_scores"].items():
                if dim in DEFAULT_DIMENSION_WEIGHTS:
                    scores[dim] = max(scores.get(dim, 0.0), score)

        return scores

    # ============================================
    # Background Decay & Cleanup
    # ============================================

    async def _decay_loop(self) -> None:
        """Apply time decay to all states periodically."""
        while self._running:
            await asyncio.sleep(3600)  # hourly
            try:
                for state in self._states.values():
                    state.apply_decay(1)  # decay 1 hour
            except Exception as e:
                log.error(f"Decay loop error: {e}")

    async def _cleanup_loop(self) -> None:
        """Remove old states with low risk."""
        while self._running:
            await asyncio.sleep(86400)  # daily
            try:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(days=30)
                to_delete = []
                for entity_id, state in self._states.items():
                    if state.last_updated < cutoff and state.composite_score < 200:
                        to_delete.append(entity_id)
                for entity_id in to_delete:
                    del self._states[entity_id]
                    log.debug(f"Removed stale risk state for {entity_id}")
            except Exception as e:
                log.error(f"Cleanup loop error: {e}")

    # ============================================
    # Public Query Methods
    # ============================================

    def get_state(self, entity_id: str) -> Optional[EntityRiskState]:
        """Get current risk state for an entity."""
        return self._states.get(entity_id)

    def get_high_risk_entities(self, min_score: float = 450) -> List[Tuple[str, float]]:
        """Get entities with composite score >= min_score."""
        return [(eid, state.composite_score) for eid, state in self._states.items()
                if state.composite_score >= min_score]

    def get_dimension_weights(self) -> Dict[str, float]:
        """Get current dimension weights."""
        return self._config["dimension_weights"].copy()

    def update_dimension_weight(self, dimension: str, weight: float) -> bool:
        """Update weight for a dimension (must sum to 1.0)."""
        if dimension not in DEFAULT_DIMENSION_WEIGHTS:
            return False
        # Update and renormalize
        self._config["dimension_weights"][dimension] = weight
        total = sum(self._config["dimension_weights"].values())
        if total != 1.0:
            # Normalize
            for dim in self._config["dimension_weights"]:
                self._config["dimension_weights"][dim] /= total
        return True

    # ============================================
    # Shutdown
    # ============================================

    def stop(self) -> None:
        """Stop the arbiter."""
        self._running = False
        if self._decay_task:
            self._decay_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        log.info("MetaRiskArbiter stopped")