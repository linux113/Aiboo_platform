"""
engines/behavioral_dna_engine.py — Behavioral DNA Engine
# SPLIT: This file is 766 lines. Suggested splits:
#   - engines/behavioral_dna_engine.py          (core engine class)
#   - engines/behavioral_dna_profile.py          (BehavioralProfile, BehavioralAnomaly dataclasses)
#   - engines/behavioral_dna_anomaly.py          (anomaly detection logic)
#   - engines/behavioral_dna_peers.py            (peer group management)

Builds and maintains behavioral profiles for every user, device, and entity.
Learns normal patterns over time and detects anomalies that indicate
compromised credentials, insider threats, or zero-day attacks.

Now supports peer groups and exposes detailed profile data for consumption
by other engines (e.g., UEBA, MetaRiskArbiter).

Part of the Zero Trust Layer 1 architecture.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ThreatEvent, AgentFinding, ThreatType, Severity,
    ResponseAction, RiskLevel, AccessRequest
)

log = logging.getLogger("BehavioralDNA")

# ============================================
# Data Models
# ============================================

@dataclass
class BehavioralProfile:
    """Behavioral profile for a single entity (user, device, IP)"""
    entity_id: str
    entity_type: str  # "user", "device", "ip"
    
    # Temporal patterns
    typical_hours: List[int] = field(default_factory=list)      # Hours when active
    typical_weekdays: List[int] = field(default_factory=list)   # Days of week (0-6)
    
    # Spatial patterns
    typical_locations: List[str] = field(default_factory=list)  # Geo locations or zones
    typical_networks: List[str] = field(default_factory=list)   # Network subnets/VPNs
    
    # Usage patterns
    typical_data_volume_gb: float = 0.5                         # Average per session
    data_volume_history: deque = field(default_factory=lambda: deque(maxlen=50))  # for std dev
    typical_applications: List[str] = field(default_factory=list)
    typical_resources: List[str] = field(default_factory=list)  # Accessed resources
    access_pattern_sequence: List[str] = field(default_factory=list)  # Last N accesses
    
    # Statistical metrics
    average_session_duration_min: float = 30.0
    average_actions_per_session: int = 10
    anomaly_threshold: float = 0.65                             # Threshold for alerting
    
    # Peer group
    peer_group: Optional[str] = None
    
    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Counters
    total_events: int = 0
    total_sessions: int = 0
    risk_score: float = 0.0
    is_anomalous: bool = False
    
    def update_temporal(self, timestamp: datetime):
        """Update temporal patterns from event timestamp"""
        hour = timestamp.hour
        if hour not in self.typical_hours:
            self.typical_hours.append(hour)
            # Keep only most common hours (max 16)
            if len(self.typical_hours) > 16:
                self.typical_hours = sorted(self.typical_hours, 
                    key=lambda h: self.typical_hours.count(h), reverse=True)[:16]
        
        weekday = timestamp.weekday()
        if weekday not in self.typical_weekdays:
            self.typical_weekdays.append(weekday)
        
        self.last_seen = timestamp
        self.last_updated = datetime.now(timezone.utc)
        self.total_events += 1
    
    def update_data_volume(self, volume_gb: float):
        """Update data volume history and running average"""
        self.data_volume_history.append(volume_gb)
        if self.data_volume_history:
            # Update rolling average
            self.typical_data_volume_gb = sum(self.data_volume_history) / len(self.data_volume_history)
    
    def get_data_volume_stats(self) -> Dict[str, float]:
        """Get mean and std dev of data volume history"""
        if not self.data_volume_history:
            return {"mean": 0.0, "std": 0.0, "count": 0}
        mean = sum(self.data_volume_history) / len(self.data_volume_history)
        variance = sum((x - mean) ** 2 for x in self.data_volume_history) / len(self.data_volume_history)
        std = math.sqrt(variance)
        return {"mean": mean, "std": std, "count": len(self.data_volume_history)}
    
    def to_dict(self) -> Dict[str, Any]:
        """Export profile as dictionary for external consumption"""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "typical_hours": self.typical_hours,
            "typical_weekdays": self.typical_weekdays,
            "typical_locations": self.typical_locations,
            "typical_networks": self.typical_networks,
            "typical_data_volume_gb": self.typical_data_volume_gb,
            "data_volume_stats": self.get_data_volume_stats(),
            "typical_applications": self.typical_applications,
            "typical_resources": self.typical_resources,
            "access_pattern_sequence": self.access_pattern_sequence[-20:],  # last 20
            "average_session_duration_min": self.average_session_duration_min,
            "average_actions_per_session": self.average_actions_per_session,
            "peer_group": self.peer_group,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_events": self.total_events,
            "total_sessions": self.total_sessions,
            "risk_score": self.risk_score,
            "is_anomalous": self.is_anomalous,
        }


@dataclass
class BehavioralAnomaly:
    """Detected behavioral anomaly"""
    entity_id: str
    entity_type: str
    anomaly_type: str  # "unusual_hour", "new_location", "data_spike", etc.
    severity: Severity
    risk_score: float
    description: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlated_events: List[str] = field(default_factory=list)


class BehavioralDNAEngine:
    """
    Behavioral DNA Engine - learns and profiles normal behavior,
    detects anomalies, and publishes findings for Zero Trust verification.
    Now with peer group support.
    """
    
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._profiles: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400 * 7)
        self._anomaly_history: List[BehavioralAnomaly] = []
        self._running = False
        
        # Peer groups: group_name -> list of entity_ids
        self._peer_groups: Dict[str, List[str]] = {}
        
        # Configuration
        self._config = {
            "profile_ttl_seconds": 86400 * 7,  # 7 days
            "min_events_for_profile": 5,
            "anomaly_decay_days": 7,
            "max_anomalies_per_entity": 100,
            "peer_groups": {},  # Can be loaded from config
        }
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        
    def start(self) -> None:
        """Start the engine - subscribe to events and start background tasks"""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        # Also listen to AgentFindings for enrichment
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        
        # Load peer groups from config if provided
        if self._config.get("peer_groups"):
            for group, members in self._config["peer_groups"].items():
                for member in members:
                    self._peer_groups.setdefault(group, []).append(member)
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        log.info("BehavioralDNAEngine started — profiling user and device behavior")
    
    # ============================================
    # Peer Group Management
    # ============================================
    
    def set_peer_group(self, entity_id: str, group_name: str) -> None:
        """Assign an entity to a peer group"""
        # Remove from existing group if any
        for g, members in self._peer_groups.items():
            if entity_id in members:
                members.remove(entity_id)
                break
        
        # Add to new group
        self._peer_groups.setdefault(group_name, []).append(entity_id)
        
        # Update profile
        profile = self._profiles.get(entity_id)
        if profile:
            profile.peer_group = group_name
        
        log.debug(f"Assigned {entity_id} to peer group {group_name}")
    
    def get_peer_group(self, entity_id: str) -> Optional[str]:
        """Get the peer group of an entity"""
        profile = self._profiles.get(entity_id)
        return profile.peer_group if profile else None
    
    def get_peer_profiles(self, group_name: str) -> List[BehavioralProfile]:
        """Get all profiles belonging to a peer group"""
        members = self._peer_groups.get(group_name, [])
        return [self._profiles[eid] for eid in members if eid in self._profiles]
    
    def get_peer_deviation(self, entity_id: str, metric: str = "data_volume") -> Dict[str, Any]:
        """
        Compute how much an entity deviates from its peers for a given metric.
        Returns: {
            "entity_value": float,
            "peer_mean": float,
            "peer_std": float,
            "z_score": float,
            "percentile": float,
            "is_outlier": bool
        }
        """
        profile = self._profiles.get(entity_id)
        if not profile or not profile.peer_group:
            return {"error": "Entity not in a peer group"}
        
        peers = self.get_peer_profiles(profile.peer_group)
        if len(peers) < 2:
            return {"error": "Insufficient peers for comparison"}
        
        # Get entity's value for the metric
        entity_value = None
        if metric == "data_volume":
            entity_value = profile.typical_data_volume_gb
        elif metric == "session_duration":
            entity_value = profile.average_session_duration_min
        elif metric == "actions_per_session":
            entity_value = profile.average_actions_per_session
        elif metric == "events_count":
            entity_value = profile.total_events
        else:
            return {"error": f"Unknown metric: {metric}"}
        
        # Collect peer values
        peer_values = []
        for p in peers:
            if p.entity_id == entity_id:
                continue
            if metric == "data_volume":
                val = p.typical_data_volume_gb
            elif metric == "session_duration":
                val = p.average_session_duration_min
            elif metric == "actions_per_session":
                val = p.average_actions_per_session
            elif metric == "events_count":
                val = p.total_events
            else:
                continue
            peer_values.append(val)
        
        if not peer_values:
            return {"error": "No valid peer values"}
        
        # Compute statistics
        mean = sum(peer_values) / len(peer_values)
        variance = sum((x - mean) ** 2 for x in peer_values) / len(peer_values)
        std = math.sqrt(variance)
        
        if std == 0:
            # All peers have same value; deviation is based on difference from mean
            z_score = 0.0
            is_outlier = False
        else:
            z_score = (entity_value - mean) / std
            is_outlier = abs(z_score) > 2.0  # 2 std deviations
        
        # Compute percentile (approximate)
        below = sum(1 for v in peer_values if v < entity_value)
        percentile = below / len(peer_values) * 100
        
        return {
            "entity_value": entity_value,
            "peer_mean": mean,
            "peer_std": std,
            "z_score": z_score,
            "percentile": percentile,
            "is_outlier": is_outlier,
            "peer_count": len(peer_values)
        }
    
    # ============================================
    # Event Handlers
    # ============================================
    
    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events to learn behavior"""
        # Extract entity from event
        entities = self._extract_entities(event)
        for entity_id, entity_type in entities:
            profile = self._get_or_create_profile(entity_id, entity_type)
            self._update_profile_from_event(profile, event)
            
            # Check for anomalies
            anomaly = self._detect_anomaly(profile, event)
            if anomaly:
                await self._publish_anomaly(anomaly, event)
    
    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests for behavioral learning"""
        # Similar to threat event but with more structured data
        user_id = request.user_id
        profile = self._get_or_create_profile(user_id, "user")
        
        # Update temporal
        profile.update_temporal(request.timestamp)
        
        # Update locations
        if request.location and request.location not in profile.typical_locations:
            profile.typical_locations.append(request.location)
            if len(profile.typical_locations) > 10:
                profile.typical_locations = profile.typical_locations[-10:]
        
        # Update networks
        if request.network and request.network not in profile.typical_networks:
            profile.typical_networks.append(request.network)
            if len(profile.typical_networks) > 5:
                profile.typical_networks = profile.typical_networks[-5:]
        
        # Update resources
        if request.resource and request.resource not in profile.typical_resources:
            profile.typical_resources.append(request.resource)
            if len(profile.typical_resources) > 20:
                profile.typical_resources = profile.typical_resources[-20:]
        
        # Update access pattern sequence
        if request.resource:
            profile.access_pattern_sequence.append(request.resource)
            if len(profile.access_pattern_sequence) > 50:
                profile.access_pattern_sequence = profile.access_pattern_sequence[-50:]
        
        profile.last_updated = datetime.now(timezone.utc)
        profile.total_sessions += 1
        
        # Detect anomalies
        anomaly = self._detect_anomaly_from_request(profile, request)
        if anomaly:
            # Create a pseudo ThreatEvent to publish
            pseudo_event = ThreatEvent(
                source="BehavioralDNAEngine",
                threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                severity=anomaly.severity,
                payload={
                    "entity_id": anomaly.entity_id,
                    "anomaly_type": anomaly.anomaly_type,
                    "description": anomaly.description,
                    "risk_score": anomaly.risk_score,
                    "request": {
                        "user_id": request.user_id,
                        "resource": request.resource,
                        "location": request.location,
                    }
                }
            )
            await self._publish_anomaly(anomaly, pseudo_event)
    
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings (e.g., confirmed threats)"""
        # Extract entity and update risk
        entity_id = finding.metadata.get("user_id") or finding.metadata.get("src_ip")
        if not entity_id:
            return
        
        profile = self._profiles.get(entity_id)
        if profile:
            # Update risk score based on finding confidence
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                profile.risk_score = min(1.0, profile.risk_score + 0.1 * finding.confidence)
            profile.last_updated = datetime.now(timezone.utc)
    
    # ============================================
    # Profile Management
    # ============================================
    
    def _get_or_create_profile(self, entity_id: str, entity_type: str) -> BehavioralProfile:
        """Get existing profile or create a new one"""
        if entity_id in self._profiles:
            return self._profiles[entity_id]
        
        # Create new profile
        profile = BehavioralProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        self._profiles[entity_id] = profile
        log.debug(f"Created new behavioral profile for {entity_type}: {entity_id}")
        return profile
    
    def _extract_entities(self, event: ThreatEvent) -> List[Tuple[str, str]]:
        """Extract entities (user, device, IP) from event"""
        p = event.payload
        entities = []
        
        # User
        if p.get("user_id"):
            entities.append((p["user_id"], "user"))
        
        # Source IP
        if p.get("src_ip"):
            entities.append((p["src_ip"], "ip"))
        
        # Device ID
        if p.get("device_id"):
            entities.append((p["device_id"], "device"))
        
        # If no entities found, use source
        if not entities and event.source:
            entities.append((event.source, "source"))
        
        return entities
    
    def _update_profile_from_event(self, profile: BehavioralProfile, event: ThreatEvent) -> None:
        """Update profile with event data"""
        p = event.payload
        
        # Temporal
        profile.update_temporal(event.timestamp)
        
        # Location
        location = p.get("location") or p.get("detected_location") or p.get("zone")
        if location and location not in profile.typical_locations:
            profile.typical_locations.append(location)
            if len(profile.typical_locations) > 10:
                profile.typical_locations = profile.typical_locations[-10:]
        
        # Data volume
        data_vol = p.get("unusual_data_volume_gb") or p.get("data_volume_gb", 0)
        if data_vol > 0:
            profile.update_data_volume(data_vol)
        
        # Resources
        resource = p.get("resource") or p.get("signature") or p.get("dst_port")
        if resource and str(resource) not in profile.typical_resources:
            profile.typical_resources.append(str(resource))
            if len(profile.typical_resources) > 20:
                profile.typical_resources = profile.typical_resources[-20:]
        
        # Applications
        app = p.get("application") or p.get("process_name")
        if app and app not in profile.typical_applications:
            profile.typical_applications.append(app)
            if len(profile.typical_applications) > 15:
                profile.typical_applications = profile.typical_applications[-15:]
        
        # Access pattern sequence
        if resource:
            profile.access_pattern_sequence.append(str(resource))
            if len(profile.access_pattern_sequence) > 50:
                profile.access_pattern_sequence = profile.access_pattern_sequence[-50:]
        
        profile.last_updated = datetime.now(timezone.utc)
        profile.total_events += 1
    
    # ============================================
    # Anomaly Detection
    # ============================================
    
    def _detect_anomaly(self, profile: BehavioralProfile, event: ThreatEvent) -> Optional[BehavioralAnomaly]:
        """Detect anomalies in event against profile"""
        # Need enough data to establish baseline
        if profile.total_events < self._config["min_events_for_profile"]:
            return None
        
        p = event.payload
        anomaly_score = 0.0
        anomaly_type = None
        description = ""
        severity = Severity.MEDIUM
        
        # 1. Check temporal anomaly (hour)
        hour = event.timestamp.hour
        if profile.typical_hours and hour not in profile.typical_hours:
            anomaly_score += 0.4
            anomaly_type = "unusual_hour"
            description = f"Activity at unusual hour: {hour}:00 (typical: {profile.typical_hours})"
            severity = Severity.MEDIUM
        
        # 2. Check location anomaly
        location = p.get("location") or p.get("detected_location") or p.get("zone")
        if location and profile.typical_locations and location not in profile.typical_locations:
            anomaly_score += 0.3
            if not anomaly_type:
                anomaly_type = "new_location"
                description = f"New location: {location}"
                severity = Severity.MEDIUM
        
        # 3. Check data volume spike
        data_vol = p.get("unusual_data_volume_gb") or p.get("data_volume_gb", 0)
        if data_vol > 0 and profile.typical_data_volume_gb > 0:
            if data_vol > profile.typical_data_volume_gb * 3:
                anomaly_score += 0.5
                if not anomaly_type:
                    anomaly_type = "data_spike"
                    description = f"Data volume spike: {data_vol:.1f}GB (typical: {profile.typical_data_volume_gb:.1f}GB)"
                    severity = Severity.HIGH
        
        # 4. Check resource access pattern anomaly
        resource = p.get("resource") or p.get("signature")
        if resource and profile.typical_resources and resource not in profile.typical_resources:
            # New resource access is less severe if it's a known type
            anomaly_score += 0.2
            if not anomaly_type:
                anomaly_type = "new_resource"
                description = f"Access to new resource: {resource}"
                severity = Severity.LOW
        
        # 5. Check sequence anomaly (if we have enough history)
        if len(profile.access_pattern_sequence) > 5 and resource:
            # Look at last 5 accesses and see if this resource appears in sequence
            recent = profile.access_pattern_sequence[-5:]
            if resource not in recent:
                # Not in recent pattern, could be deviation
                anomaly_score += 0.1
        
        # 6. Check network anomaly
        network = p.get("network") or p.get("network_info", {}).get("type")
        if network and profile.typical_networks and network not in profile.typical_networks:
            anomaly_score += 0.2
            if not anomaly_type:
                anomaly_type = "new_network"
                description = f"New network: {network}"
                severity = Severity.MEDIUM
        
        # If anomaly score exceeds threshold, create anomaly
        if anomaly_score >= profile.anomaly_threshold:
            risk_level = self._score_to_risk(anomaly_score)
            return BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type=anomaly_type or "general_anomaly",
                severity=severity,
                risk_score=anomaly_score,
                description=description or f"Behavioral anomaly (score: {anomaly_score:.2f})",
                timestamp=event.timestamp
            )
        
        return None
    
    def _detect_anomaly_from_request(self, profile: BehavioralProfile, request: AccessRequest) -> Optional[BehavioralAnomaly]:
        """Detect anomalies from access request"""
        if profile.total_sessions < 3:  # Need some history
            return None
        
        anomaly_score = 0.0
        anomaly_type = None
        description = ""
        severity = Severity.MEDIUM
        
        # Hour check
        hour = request.timestamp.hour
        if profile.typical_hours and hour not in profile.typical_hours:
            anomaly_score += 0.4
            anomaly_type = "unusual_hour"
            description = f"Access at unusual hour: {hour}:00"
            severity = Severity.MEDIUM
        
        # Location check
        if request.location and profile.typical_locations and request.location not in profile.typical_locations:
            anomaly_score += 0.3
            if not anomaly_type:
                anomaly_type = "new_location"
                description = f"Access from new location: {request.location}"
                severity = Severity.HIGH
        
        # Network check
        if request.network and profile.typical_networks and request.network not in profile.typical_networks:
            anomaly_score += 0.2
            if not anomaly_type:
                anomaly_type = "new_network"
                description = f"Access from new network: {request.network}"
                severity = Severity.MEDIUM
        
        # Resource check
        if request.resource and profile.typical_resources and request.resource not in profile.typical_resources:
            anomaly_score += 0.2
            if not anomaly_type:
                anomaly_type = "new_resource"
                description = f"Access to new resource: {request.resource}"
                severity = Severity.MEDIUM
        
        if anomaly_score >= profile.anomaly_threshold:
            return BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type=anomaly_type or "access_anomaly",
                severity=severity,
                risk_score=anomaly_score,
                description=description or f"Access anomaly (score: {anomaly_score:.2f})",
                timestamp=request.timestamp
            )
        
        return None
    
    def _score_to_risk(self, score: float) -> RiskLevel:
        """Convert anomaly score to risk level"""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    # ============================================
    # Publishing
    # ============================================
    
    async def _publish_anomaly(self, anomaly: BehavioralAnomaly, event: ThreatEvent) -> None:
        """Publish anomaly as a ThreatEvent"""
        # Create a ThreatEvent for the anomaly
        anomaly_event = ThreatEvent(
            source="BehavioralDNAEngine",
            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
            severity=anomaly.severity,
            payload={
                "entity_id": anomaly.entity_id,
                "entity_type": anomaly.entity_type,
                "anomaly_type": anomaly.anomaly_type,
                "description": anomaly.description,
                "risk_score": anomaly.risk_score,
                "correlated_events": anomaly.correlated_events,
                "original_event_id": event.event_id if event else None,
                "peer_deviation": self.get_peer_deviation(anomaly.entity_id) if anomaly.entity_id in self._profiles else None,
            },
            timestamp=anomaly.timestamp
        )
        
        await self.bus.publish(anomaly_event)
        
        # Also log it
        log.warning(
            "[BEHAVIORAL ANOMALY] %s %s: %s (risk=%.2f)",
            anomaly.entity_type, anomaly.entity_id,
            anomaly.description, anomaly.risk_score
        )
        
        # Store in history
        self._anomaly_history.append(anomaly)
        if len(self._anomaly_history) > 10000:
            self._anomaly_history = self._anomaly_history[-5000:]
    
    # ============================================
    # Cleanup and Maintenance
    # ============================================
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup for expired profiles"""
        while self._running:
            await asyncio.sleep(3600)  # Run every hour
            
            try:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(seconds=self._config["profile_ttl_seconds"])
                
                expired = []
                for entity_id, profile in self._profiles.items():
                    if profile.last_seen < cutoff:
                        expired.append(entity_id)
                
                for entity_id in expired:
                    # Also remove from peer groups
                    for group, members in self._peer_groups.items():
                        if entity_id in members:
                            members.remove(entity_id)
                    del self._profiles[entity_id]
                    log.debug(f"Removed expired profile: {entity_id}")
                
                # Also clean old anomalies
                if len(self._anomaly_history) > 5000:
                    self._anomaly_history = self._anomaly_history[-3000:]
                    
            except Exception as e:
                log.error(f"Error in cleanup loop: {e}")
    
    def stop(self) -> None:
        """Stop the engine"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        log.info("BehavioralDNAEngine stopped")
    
    # ============================================
    # Query Methods (for other components)
    # ============================================
    
    def get_profile(self, entity_id: str) -> Optional[BehavioralProfile]:
        """Get behavioral profile for an entity"""
        return self._profiles.get(entity_id)
    
    def get_profile_dict(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get profile as dictionary for external consumption"""
        profile = self._profiles.get(entity_id)
        return profile.to_dict() if profile else None
    
    def get_all_profiles(self) -> List[BehavioralProfile]:
        """Get all active profiles"""
        return list(self._profiles.values())
    
    def get_all_profiles_dict(self) -> List[Dict[str, Any]]:
        """Get all profiles as dictionaries"""
        return [p.to_dict() for p in self._profiles.values()]
    
    def get_anomalies(self, entity_id: Optional[str] = None, 
                     since: Optional[datetime] = None) -> List[BehavioralAnomaly]:
        """Get anomalies, optionally filtered by entity or time"""
        anomalies = self._anomaly_history
        if entity_id:
            anomalies = [a for a in anomalies if a.entity_id == entity_id]
        if since:
            since_aware = since if since.tzinfo is not None else since.replace(tzinfo=timezone.utc)
            anomalies = [a for a in anomalies if (a.timestamp if a.timestamp.tzinfo is not None else a.timestamp.replace(tzinfo=timezone.utc)) >= since_aware]
        return sorted(anomalies, key=lambda a: a.timestamp, reverse=True)
    
    def get_risk_score(self, entity_id: str) -> float:
        """Get current risk score for entity"""
        profile = self._profiles.get(entity_id)
        return profile.risk_score if profile else 0.0
    
    def is_anomalous(self, entity_id: str) -> bool:
        """Check if entity is currently flagged as anomalous"""
        profile = self._profiles.get(entity_id)
        return profile.is_anomalous if profile else False
    
    # ============================================
    # Peer Group Queries (public)
    # ============================================
    
    def get_all_peer_groups(self) -> Dict[str, List[str]]:
        """Get all peer group memberships"""
        return self._peer_groups.copy()
    
    def get_peer_group_members(self, group_name: str) -> List[str]:
        """Get members of a specific peer group"""
        return self._peer_groups.get(group_name, []).copy()
    
    def get_entity_peer_deviation(self, entity_id: str, metric: str = "data_volume") -> Dict[str, Any]:
        """Public wrapper for peer deviation calculation"""
        return self.get_peer_deviation(entity_id, metric)