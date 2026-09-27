"""
engines/risk_scoring_engine.py — Dynamic Risk Scoring Engine

Continuously calculates and updates risk scores for all entities
(users, devices, IPs, sessions) based on real-time events, historical
behavior, and threat intelligence.

Now integrates with MetaRiskArbiter: for entities that have a composite
score from the arbiter, that score overrides the locally computed score.

Scores are used by the Zero Trust PDP to make access decisions.
Implements dynamic risk scoring with time decay, factor weighting,
and correlation between entity types.

Part of Layer 1 Zero Trust architecture.
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from collections import defaultdict
from enum import Enum
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ThreatEvent, ThreatType, Severity, AgentFinding,
    AccessRequest, RiskLevel, ResponseAction
)

log = logging.getLogger("RiskScoringEngine")

# ============================================
# Risk Factor Definitions
# ============================================

class RiskFactor(str, Enum):
    """Factors that contribute to risk score"""
    IDENTITY = "identity"
    DEVICE = "device"
    NETWORK = "network"
    LOCATION = "location"
    BEHAVIORAL = "behavioral"
    GEO_VELOCITY = "geo_velocity"
    THREAT_INTEL = "threat_intel"
    PRIVILEGE = "privilege"
    SESSION_AGE = "session_age"
    ATTEMPT_RATE = "attempt_rate"
    ANOMALY_COUNT = "anomaly_count"
    RECENT_BLOCK = "recent_block"

# Factor weights (sum to 1.0)
DEFAULT_WEIGHTS = {
    RiskFactor.IDENTITY: 0.20,
    RiskFactor.DEVICE: 0.20,
    RiskFactor.NETWORK: 0.10,
    RiskFactor.LOCATION: 0.10,
    RiskFactor.BEHAVIORAL: 0.15,
    RiskFactor.GEO_VELOCITY: 0.10,
    RiskFactor.THREAT_INTEL: 0.10,
    RiskFactor.PRIVILEGE: 0.05,
}

# Decay rates (per hour) - scores decay towards zero
DECAY_RATES = {
    "low": 0.01,      # 1% per hour
    "medium": 0.02,   # 2% per hour
    "high": 0.05,     # 5% per hour
    "critical": 0.10, # 10% per hour
}

# Minimum events required for stable risk score
MIN_EVENTS_FOR_STABLE = 5


@dataclass
class EntityRisk:
    """Risk state for a single entity"""
    entity_id: str
    entity_type: str  # "user", "device", "ip", "session"
    
    # Risk scores (0.0 to 1.0)
    overall_risk: float = 0.0
    factors: Dict[RiskFactor, float] = field(default_factory=dict)
    
    # Flag to indicate if overall_risk is from MetaRiskArbiter
    _has_arbiter_score: bool = False
    
    # History
    risk_history: List[Tuple[datetime, float]] = field(default_factory=list)
    max_history_size: int = 100
    
    # Event counters
    total_events: int = 0
    high_severity_events: int = 0
    blocks_count: int = 0
    anomalies_count: int = 0
    
    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_decay: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Stability
    is_stable: bool = False
    
    def update_factor(self, factor: RiskFactor, value: float):
        """Update a specific factor score"""
        self.factors[factor] = min(1.0, max(0.0, value))
        self.last_updated = datetime.now(timezone.utc)
        self._recalculate_overall()
    
    def set_arbiter_score(self, score: float, risk_level: RiskLevel):
        """Set the overall risk from MetaRiskArbiter"""
        self.overall_risk = min(1.0, max(0.0, score))
        self._has_arbiter_score = True
        self.last_updated = datetime.now(timezone.utc)
        # Track history
        self.risk_history.append((datetime.now(timezone.utc), self.overall_risk))
        if len(self.risk_history) > self.max_history_size:
            self.risk_history = self.risk_history[-self.max_history_size:]
    
    def _recalculate_overall(self):
        """Recalculate overall risk from factors, unless overridden by arbiter"""
        if self._has_arbiter_score:
            # Keep the arbiter score; do not recalculate from factors
            return
        
        if not self.factors:
            self.overall_risk = 0.0
            return
        
        # Weighted sum of factors
        total = 0.0
        weight_sum = 0.0
        for factor, weight in DEFAULT_WEIGHTS.items():
            if factor in self.factors:
                total += self.factors[factor] * weight
                weight_sum += weight
        
        if weight_sum > 0:
            self.overall_risk = total / weight_sum
        else:
            self.overall_risk = 0.0
        
        self.overall_risk = min(1.0, max(0.0, self.overall_risk))
        
        # Track history
        self.risk_history.append((datetime.now(timezone.utc), self.overall_risk))
        if len(self.risk_history) > self.max_history_size:
            self.risk_history = self.risk_history[-self.max_history_size:]
    
    def apply_decay(self, decay_rate: float):
        """Apply time decay to overall risk (only if not controlled by arbiter)"""
        if self._has_arbiter_score:
            # Do not decay arbiter-controlled score; the arbiter handles it
            return
        
        # Decay factors
        for factor in list(self.factors.keys()):
            current = self.factors[factor]
            decayed = current * (1 - decay_rate)
            self.factors[factor] = max(0.0, decayed)
        
        self._recalculate_overall()
        self.last_decay = datetime.now(timezone.utc)
    
    def add_event(self, severity: Severity, is_block: bool = False):
        """Record an event for this entity"""
        self.total_events += 1
        if severity in (Severity.HIGH, Severity.CRITICAL):
            self.high_severity_events += 1
        if is_block:
            self.blocks_count += 1
        self.last_updated = datetime.now(timezone.utc)
        
        # Check stability
        if self.total_events >= MIN_EVENTS_FOR_STABLE:
            self.is_stable = True
    
    def get_risk_level(self) -> RiskLevel:
        """Convert overall risk to RiskLevel"""
        if self.overall_risk >= 0.9:
            return RiskLevel.CRITICAL
        elif self.overall_risk >= 0.7:
            return RiskLevel.HIGH
        elif self.overall_risk >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW


class RiskScoringEngine:
    """
    Dynamic risk scoring engine for Zero Trust.
    
    Maintains risk scores for all entities, updates them based on events,
    applies time decay, and provides query interfaces.
    Now integrates with MetaRiskArbiter for composite risk scores.
    """
    
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._entities: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        self._correlations: Dict[str, List[str]] = defaultdict(list)
        self._running = False
        
        # Configuration
        self._config = {
            "weights": DEFAULT_WEIGHTS.copy(),
            "decay_base_rate": 0.02,  # 2% per hour
            "decay_max_rate": 0.15,   # 15% per hour
            "stable_entity_threshold": MIN_EVENTS_FOR_STABLE,
        }
        
        # Background task
        self._decay_task: Optional[asyncio.Task] = None
        self._decay_interval_seconds = 300  # 5 minutes
        
        log.info("RiskScoringEngine initialized")
    
    def start(self) -> None:
        """Start the engine - subscribe to events and start decay loop"""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        
        self._running = True
        self._decay_task = asyncio.create_task(self._decay_loop())
        
        log.info("RiskScoringEngine started")
    
    # ============================================
    # Event Handlers
    # ============================================
    
    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events - update risk scores"""
        # Extract entities
        entities = self._extract_entities(event)
        for entity_id, entity_type, factor, score in entities:
            risk = self._get_or_create_entity(entity_id, entity_type)
            
            # Update factor
            if factor and score is not None:
                risk.update_factor(factor, score)
            else:
                # Derive factor from threat type and severity
                factor, score = self._derive_risk_from_threat(event)
                if factor:
                    risk.update_factor(factor, score)
            
            # Record event
            risk.add_event(event.severity)
            
            # If threat is critical, also increase related entities' risks
            if event.severity == Severity.CRITICAL:
                await self._propagate_risk(entity_id, 0.1)
    
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Process agent findings - update risk based on agent confidence"""
        # Special handling for MetaRiskArbiter findings
        if finding.agent_name == "MetaRiskArbiter":
            await self._update_from_meta_risk(finding)
            return
        
        # Extract entity
        entity_id = finding.metadata.get("user_id") or finding.metadata.get("src_ip") or finding.metadata.get("device_id")
        if not entity_id:
            return
        
        risk = self._get_or_create_entity(entity_id, "unknown")
        
        # Determine factor from agent type
        if "identity" in finding.agent_name.lower():
            factor = RiskFactor.IDENTITY
        elif "device" in finding.agent_name.lower() or "fingerprint" in finding.agent_name.lower():
            factor = RiskFactor.DEVICE
        elif "network" in finding.agent_name.lower() or "traffic" in finding.agent_name.lower():
            factor = RiskFactor.NETWORK
        elif "behavior" in finding.agent_name.lower():
            factor = RiskFactor.BEHAVIORAL
        else:
            factor = RiskFactor.THREAT_INTEL
        
        # Risk increase based on finding confidence and severity
        base_increase = finding.confidence * 0.3
        if finding.severity == Severity.CRITICAL:
            base_increase *= 1.5
        elif finding.severity == Severity.HIGH:
            base_increase *= 1.2
        
        current = risk.factors.get(factor, 0.0)
        new_score = min(1.0, current + base_increase)
        risk.update_factor(factor, new_score)
        risk.add_event(finding.severity, is_block=(ResponseAction.BLOCK_ACCESS in finding.actions))
    
    async def _update_from_meta_risk(self, finding: AgentFinding):
        """Update entity risk from MetaRiskArbiter's composite score"""
        meta = finding.metadata
        entity_id = meta.get("entity_id")
        if not entity_id:
            log.warning("MetaRiskArbiter finding missing entity_id")
            return
        
        # Determine entity type
        entity_type = meta.get("entity_type", "unknown")
        risk = self._get_or_create_entity(entity_id, entity_type)
        
        # Get composite score (0-1000) and convert to 0-1
        composite_score = meta.get("composite_score", 0.0) / 1000.0
        risk_level_str = meta.get("risk_level", "low")
        # Convert to RiskLevel enum
        risk_level = RiskLevel(risk_level_str) if risk_level_str in RiskLevel._value2member_map_ else RiskLevel.LOW
        
        # Set the arbiter score (this will prevent factor-based recomputation)
        risk.set_arbiter_score(composite_score, risk_level)
        
        # Also update factors from dimension_scores if available
        dimension_scores = meta.get("dimension_scores", {})
        # Map dimension names to RiskFactor enum
        dim_to_factor = {
            "behavioral": RiskFactor.BEHAVIORAL,
            "threat_intel": RiskFactor.THREAT_INTEL,
            "physical": RiskFactor.LOCATION,  # Map physical to location for now
            "insider": RiskFactor.BEHAVIORAL,  # Insider maps to behavioral
            "device": RiskFactor.DEVICE,
            "network": RiskFactor.NETWORK,
        }
        for dim, score in dimension_scores.items():
            factor = dim_to_factor.get(dim)
            if factor:
                risk.factors[factor] = min(1.0, max(0.0, score))
        
        # Record event
        risk.add_event(finding.severity)
        
        log.debug(f"Updated risk for {entity_id} from MetaRiskArbiter: score={composite_score:.2f}")
    
    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests - update risk based on request context"""
        # User risk
        user_risk = self._get_or_create_entity(request.user_id, "user")
        # Update location/network factors from request
        if request.location:
            # If location is unusual, increase location risk
            # (in real implementation, would compare to typical)
            pass
        if request.network:
            if request.network not in ["corporate", "vpn", "trusted"]:
                user_risk.update_factor(RiskFactor.NETWORK, 
                                       user_risk.factors.get(RiskFactor.NETWORK, 0.0) + 0.1)
        
        # Update attempt rate (if too many attempts)
        user_risk.add_event(Severity.MEDIUM)
    
    # ============================================
    # Core Risk Functions
    # ============================================
    
    def _get_or_create_entity(self, entity_id: str, entity_type: str) -> EntityRisk:
        """Get existing entity or create new one"""
        if entity_id not in self._entities:
            risk = EntityRisk(entity_id=entity_id, entity_type=entity_type)
            self._entities[entity_id] = risk
            log.debug(f"Created new risk entity: {entity_id} ({entity_type})")
        return self._entities[entity_id]
    
    def _extract_entities(self, event: ThreatEvent) -> List[Tuple[str, str, Optional[RiskFactor], Optional[float]]]:
        """Extract entities and risk updates from event"""
        p = event.payload
        results = []
        
        # User
        user_id = p.get("user_id")
        if user_id:
            results.append((user_id, "user", RiskFactor.IDENTITY, self._score_identity(event)))
        
        # Source IP
        src_ip = p.get("src_ip")
        if src_ip:
            results.append((src_ip, "ip", RiskFactor.NETWORK, self._score_network(event)))
        
        # Device
        device_id = p.get("device_id") or p.get("device_info", {}).get("device_id")
        if device_id:
            results.append((device_id, "device", RiskFactor.DEVICE, self._score_device(event)))
        
        # Also add behavioral if present
        if event.threat_type == ThreatType.ANOMALOUS_BEHAVIOR:
            # For anomalous behavior, we update behavioral factor for the user
            if user_id:
                results.append((user_id, "user", RiskFactor.BEHAVIORAL, event.severity.weight / 4))
        
        return results
    
    def _score_identity(self, event: ThreatEvent) -> float:
        """Calculate identity risk from event"""
        p = event.payload
        score = 0.0
        if event.threat_type == ThreatType.IDENTITY_MISMATCH:
            score += 0.4
            if p.get("biometric_score", 1.0) < 0.5:
                score += 0.3
            if p.get("claimed_location") and p.get("detected_location") and \
               p["claimed_location"] != p["detected_location"]:
                score += 0.2
        elif event.threat_type == ThreatType.INSIDER_THREAT:
            score += 0.3
        # Add severity weight
        score += (event.severity.weight - 1) * 0.1
        return min(1.0, score)
    
    def _score_network(self, event: ThreatEvent) -> float:
        """Calculate network risk from event"""
        p = event.payload
        score = 0.0
        if event.threat_type == ThreatType.NETWORK_INTRUSION:
            score += 0.3
            rate = p.get("packet_rate", 0)
            if rate > 10000:
                score += 0.3
            elif rate > 5000:
                score += 0.2
            signature = p.get("signature", "")
            if signature in {"RANSOMWARE_C2", "RCE_EXPLOIT", "DATA_EXFIL"}:
                score += 0.4
        return min(1.0, score)
    
    def _score_device(self, event: ThreatEvent) -> float:
        """Calculate device risk from event"""
        p = event.payload
        score = 0.0
        if event.threat_type == ThreatType.DEVICE_HEALTH_FAIL:
            score += 0.5
        if p.get("root_detected") or p.get("jailbreak_detected"):
            score += 0.3
        if not p.get("antivirus_active", True):
            score += 0.2
        return min(1.0, score)
    
    def _derive_risk_from_threat(self, event: ThreatEvent) -> Tuple[Optional[RiskFactor], float]:
        """Derive factor and score from threat type"""
        mapping = {
            ThreatType.NETWORK_INTRUSION: (RiskFactor.NETWORK, 0.4),
            ThreatType.IDENTITY_MISMATCH: (RiskFactor.IDENTITY, 0.5),
            ThreatType.PHYSICAL_INTRUSION: (RiskFactor.LOCATION, 0.5),
            ThreatType.INSIDER_THREAT: (RiskFactor.BEHAVIORAL, 0.4),
            ThreatType.ANOMALOUS_BEHAVIOR: (RiskFactor.BEHAVIORAL, 0.3),
        }
        factor, base = mapping.get(event.threat_type, (None, 0.0))
        if factor:
            score = base + (event.severity.weight - 1) * 0.1
            return factor, min(1.0, score)
        return None, 0.0
    
    async def _propagate_risk(self, entity_id: str, propagation_factor: float):
        """Propagate risk to related entities (e.g., user to devices)"""
        # In real implementation, would query relationships
        # For now, just log
        log.debug(f"Propagating risk from {entity_id} with factor {propagation_factor}")
    
    # ============================================
    # Decay Loop
    # ============================================
    
    async def _decay_loop(self):
        """Apply time decay to all entities periodically"""
        while self._running:
            await asyncio.sleep(self._decay_interval_seconds)
            try:
                now = datetime.now(timezone.utc)
                for entity_id, risk in list(self._entities.items()):
                    # Calculate decay rate based on current risk level
                    level = risk.get_risk_level()
                    rate_map = {
                        RiskLevel.LOW: 0.01,
                        RiskLevel.MEDIUM: 0.02,
                        RiskLevel.HIGH: 0.03,
                        RiskLevel.CRITICAL: 0.05,
                    }
                    decay_rate = rate_map.get(level, 0.02)
                    # Apply decay
                    hours = (now - risk.last_decay).total_seconds() / 3600
                    if hours > 0:
                        total_decay = 1 - (decay_rate ** hours)  # exponential decay
                        risk.apply_decay(total_decay)
                    
                    # If risk is very low and entity hasn't been seen for a while, consider cleanup
                    if risk.overall_risk < 0.01 and risk.total_events < MIN_EVENTS_FOR_STABLE:
                        # Could remove if old, but keep for now
                        pass
            except Exception as e:
                log.error(f"Error in decay loop: {e}")
    
    # ============================================
    # Public Query Methods
    # ============================================
    
    def get_entity_risk(self, entity_id: str) -> Optional[EntityRisk]:
        """Get risk state for an entity"""
        return self._entities.get(entity_id)
    
    def get_overall_risk(self, entity_id: str) -> float:
        """Get overall risk score for an entity"""
        risk = self._entities.get(entity_id)
        return risk.overall_risk if risk else 0.0
    
    def get_risk_level(self, entity_id: str) -> RiskLevel:
        """Get risk level for an entity"""
        risk = self._entities.get(entity_id)
        if risk:
            return risk.get_risk_level()
        return RiskLevel.LOW
    
    def get_factor_score(self, entity_id: str, factor: RiskFactor) -> float:
        """Get specific factor score for an entity"""
        risk = self._entities.get(entity_id)
        if risk:
            return risk.factors.get(factor, 0.0)
        return 0.0
    
    def get_risk_history(self, entity_id: str, limit: int = 20) -> List[Tuple[datetime, float]]:
        """Get risk history for an entity"""
        risk = self._entities.get(entity_id)
        if risk:
            return risk.risk_history[-limit:]
        return []
    
    def get_high_risk_entities(self, threshold: float = 0.7) -> List[Tuple[str, float]]:
        """Get entities with risk above threshold"""
        results = []
        for entity_id, risk in self._entities.items():
            if risk.overall_risk >= threshold:
                results.append((entity_id, risk.overall_risk))
        return sorted(results, key=lambda x: x[1], reverse=True)
    
    def get_entity_count(self) -> int:
        """Get total number of tracked entities"""
        return len(self._entities)
    
    def update_factor(self, entity_id: str, factor: RiskFactor, value: float):
        """Manually update a factor for an entity"""
        risk = self._get_or_create_entity(entity_id, "unknown")
        risk.update_factor(factor, value)
        risk.last_updated = datetime.now(timezone.utc)
    
    # ============================================
    # Configuration and Maintenance
    # ============================================
    
    def get_config(self) -> Dict:
        return self._config.copy()
    
    def update_config(self, new_config: Dict):
        self._config.update(new_config)
    
    def stop(self) -> None:
        self._running = False
        if self._decay_task:
            self._decay_task.cancel()
        log.info("RiskScoringEngine stopped")