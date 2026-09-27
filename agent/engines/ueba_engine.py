"""
engines/ueba_engine.py — User and Entity Behavior Analytics (UEBA) Engine

Builds and maintains detailed behavioral profiles for users, devices, and service accounts.
Supports peer group analysis, multi-dimensional anomaly scoring, and publishes
behavioral anomaly events to the event bus.

Part of Layer 2: Detection & Intelligence.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple, Set
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ThreatEvent, ThreatType, Severity,
    AccessRequest, AgentFinding
)

log = logging.getLogger("UEBAEngine")

# ============================================
# Configuration Constants
# ============================================

# Window sizes for rolling statistics (in events or seconds)
BEHAVIORAL_WINDOW_EVENTS = 100          # number of events to keep for sequence analysis
TIME_WINDOW_HOURS = 24                  # for hourly activity patterns
DATA_VOLUME_WINDOW_DAYS = 90            # for data volume baselines

# Anomaly thresholds (Z-score)
ANOMALY_Z_THRESHOLD = 2.5               # events with Z-score > this are anomalous
PEER_ANOMALY_Z_THRESHOLD = 2.0          # deviation from peer group

# Weight for each signal when computing overall anomaly score
SIGNAL_WEIGHTS = {
    "login_time": 0.15,
    "data_volume": 0.20,
    "lateral_movement": 0.15,
    "email_graph": 0.10,
    "app_usage": 0.10,
    "after_hours": 0.15,
    "sensitive_access": 0.15,
}

# Minimum events required for a stable individual baseline
MIN_EVENTS_FOR_BASELINE = 10

# Peer group configuration (in production, this would come from a user directory or config)
PEER_GROUPS = {
    "finance": ["finance_user1", "finance_user2", "finance_user3"],
    "engineering": ["eng_user1", "eng_user2", "eng_user3"],
    "hr": ["hr_user1", "hr_user2"],
    "executive": ["exec1", "exec2"],
}
# Role mapping for each user (simplified)
USER_ROLE = {
    "finance_user1": "finance",
    "finance_user2": "finance",
    "finance_user3": "finance",
    "eng_user1": "engineering",
    "eng_user2": "engineering",
    "eng_user3": "engineering",
    "hr_user1": "hr",
    "hr_user2": "hr",
    "exec1": "executive",
    "exec2": "executive",
}

# Sensitive resources (for sensitive access tracking)
SENSITIVE_RESOURCES = {
    "/api/v1/payroll",
    "/api/v1/employee_data",
    "/admin/console",
    "/finance/reports",
    "server_room",
    "data_vault",
}


@dataclass
class BehavioralProfile:
    """Extended behavioral profile for an entity."""
    entity_id: str
    entity_type: str  # "user", "device", "service_account"

    # Temporal patterns
    login_hours: List[int] = field(default_factory=list)        # hours of login (0-23)
    login_weekdays: List[int] = field(default_factory=list)     # days of week (0-6)

    # Data volume (rolling average)
    data_volume_gb: List[float] = field(default_factory=list)   # per session or per day
    avg_data_volume_gb: float = 0.0
    data_volume_std: float = 0.0

    # Lateral movement: count of unique destinations per time window
    lateral_destinations: List[Set[str]] = field(default_factory=list)  # sets of IPs/hosts
    avg_lateral_count: float = 0.0
    lateral_std: float = 0.0

    # Email graph: new recipients per session (if applicable)
    new_recipients_per_session: List[int] = field(default_factory=list)
    avg_new_recipients: float = 0.0
    new_recipients_std: float = 0.0

    # Application usage sequences (last N apps)
    app_sequence: List[str] = field(default_factory=list)
    app_usage_counts: Dict[str, int] = field(default_factory=dict)

    # After-hours activity index (0-1) per session
    after_hours_index: List[float] = field(default_factory=list)
    avg_after_hours_index: float = 0.0
    after_hours_std: float = 0.0

    # Sensitive resource access count per time window
    sensitive_access_count: List[int] = field(default_factory=list)
    avg_sensitive_access: float = 0.0
    sensitive_std: float = 0.0

    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Counters
    total_events: int = 0
    is_stable: bool = False

    def update_temporal(self, timestamp: datetime):
        """Update temporal patterns."""
        hour = timestamp.hour
        if hour not in self.login_hours:
            self.login_hours.append(hour)
        weekday = timestamp.weekday()
        if weekday not in self.login_weekdays:
            self.login_weekdays.append(weekday)
        self.last_seen = timestamp
        self.last_updated = datetime.now(timezone.utc)

    def add_data_volume(self, volume_gb: float):
        """Add data volume measurement."""
        self.data_volume_gb.append(volume_gb)
        if len(self.data_volume_gb) > BEHAVIORAL_WINDOW_EVENTS:
            self.data_volume_gb = self.data_volume_gb[-BEHAVIORAL_WINDOW_EVENTS:]
        self._update_stats("data_volume")

    def add_lateral_destinations(self, destinations: Set[str]):
        """Add set of lateral movement destinations."""
        self.lateral_destinations.append(destinations)
        if len(self.lateral_destinations) > BEHAVIORAL_WINDOW_EVENTS:
            self.lateral_destinations = self.lateral_destinations[-BEHAVIORAL_WINDOW_EVENTS:]
        self._update_stats("lateral")

    def add_new_recipients(self, count: int):
        """Add count of new email recipients."""
        self.new_recipients_per_session.append(count)
        if len(self.new_recipients_per_session) > BEHAVIORAL_WINDOW_EVENTS:
            self.new_recipients_per_session = self.new_recipients_per_session[-BEHAVIORAL_WINDOW_EVENTS:]
        self._update_stats("email")

    def add_app_usage(self, app: str):
        """Track application usage."""
        self.app_sequence.append(app)
        if len(self.app_sequence) > BEHAVIORAL_WINDOW_EVENTS:
            self.app_sequence = self.app_sequence[-BEHAVIORAL_WINDOW_EVENTS:]
        self.app_usage_counts[app] = self.app_usage_counts.get(app, 0) + 1

    def add_after_hours_index(self, index: float):
        """Add after-hours activity index (0 = business hours, 1 = fully off-hours)."""
        self.after_hours_index.append(index)
        if len(self.after_hours_index) > BEHAVIORAL_WINDOW_EVENTS:
            self.after_hours_index = self.after_hours_index[-BEHAVIORAL_WINDOW_EVENTS:]
        self._update_stats("after_hours")

    def add_sensitive_access(self, count: int):
        """Add number of sensitive resource accesses in a window."""
        self.sensitive_access_count.append(count)
        if len(self.sensitive_access_count) > BEHAVIORAL_WINDOW_EVENTS:
            self.sensitive_access_count = self.sensitive_access_count[-BEHAVIORAL_WINDOW_EVENTS:]
        self._update_stats("sensitive")

    def _update_stats(self, attr: str):
        """Update mean and std for a given attribute list."""
        lst = getattr(self, attr, [])
        if len(lst) < MIN_EVENTS_FOR_BASELINE:
            setattr(self, f"{attr}_std", 0.0)
            return
        mean = sum(lst) / len(lst)
        variance = sum((x - mean) ** 2 for x in lst) / len(lst)
        std = math.sqrt(variance)
        setattr(self, f"avg_{attr}", mean)
        setattr(self, f"{attr}_std", std)
        # Check stability
        if self.total_events >= MIN_EVENTS_FOR_BASELINE:
            self.is_stable = True

    def get_z_score(self, value: float, attr: str) -> float:
        """Calculate Z-score for a given value against the attribute's baseline."""
        mean = getattr(self, f"avg_{attr}", 0.0)
        std = getattr(self, f"{attr}_std", 0.0)
        if std == 0:
            return 0.0
        return abs((value - mean) / std)


class UEBAEngine:
    """
    User and Entity Behavior Analytics Engine.
    Builds detailed profiles, performs peer group analysis, and publishes
    behavioral anomalies.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._profiles: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400 * 7)
        self._peer_groups = PEER_GROUPS
        self._user_role = USER_ROLE
        self._running = False

        # Background cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

        # Config (could be loaded from external file)
        self._config = {
            "peer_groups": PEER_GROUPS,
            "user_role": USER_ROLE,
            "sensitive_resources": SENSITIVE_RESOURCES,
            "signal_weights": SIGNAL_WEIGHTS,
            "anomaly_z_threshold": ANOMALY_Z_THRESHOLD,
            "peer_anomaly_z_threshold": PEER_ANOMALY_Z_THRESHOLD,
            "profile_ttl_seconds": 86400 * 7,  # 7 days
        }

        log.info("UEBAEngine initialized")

    def start(self) -> None:
        """Start the engine: subscribe to events and start cleanup."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("UEBAEngine started — monitoring user and entity behavior")

    # ============================================
    # Event Handlers
    # ============================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events to update profiles and detect anomalies."""
        # Extract entities from event
        entities = self._extract_entities(event)
        for entity_id, entity_type in entities:
            profile = self._get_or_create_profile(entity_id, entity_type)
            self._update_profile_from_event(profile, event)

            # After update, check for anomalies
            await self._check_anomalies(profile, event)

    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests (structured data)."""
        # User
        user_id = request.user_id
        profile = self._get_or_create_profile(user_id, "user")
        self._update_profile_from_request(profile, request)

        # Check anomalies
        # We'll create a pseudo-event for anomaly detection
        pseudo_event = ThreatEvent(
            source="UEBAEngine",
            threat_type=ThreatType.ACCESS_REQUEST,
            severity=Severity.LOW,
            payload={
                "user_id": user_id,
                "resource": request.resource,
                "location": request.location,
                "network": request.network,
                "timestamp": request.timestamp.isoformat(),
            }
        )
        await self._check_anomalies(profile, pseudo_event)

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings (e.g., confirmed threats)."""
        # If an agent confirms a behavioral anomaly, we could update risk scores
        # but we primarily use this to adjust profiles indirectly.
        pass

    # ============================================
    # Profile Management
    # ============================================

    def _get_or_create_profile(self, entity_id: str, entity_type: str) -> BehavioralProfile:
        """Get existing profile or create a new one."""
        if entity_id in self._profiles:
            return self._profiles[entity_id]

        profile = BehavioralProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            first_seen=datetime.now(timezone.utc),
        )
        self._profiles[entity_id] = profile
        log.debug(f"Created new UEBA profile for {entity_type}: {entity_id}")
        return profile

    def _extract_entities(self, event: ThreatEvent) -> List[Tuple[str, str]]:
        """Extract entities (user, device, IP) from event."""
        p = event.payload
        entities = []
        if p.get("user_id"):
            entities.append((p["user_id"], "user"))
        if p.get("src_ip"):
            entities.append((p["src_ip"], "ip"))
        if p.get("device_id"):
            entities.append((p["device_id"], "device"))
        # If no entities, use source
        if not entities and event.source:
            entities.append((event.source, "source"))
        return entities

    def _update_profile_from_event(self, profile: BehavioralProfile, event: ThreatEvent) -> None:
        """Update profile with event data."""
        p = event.payload
        now = event.timestamp

        # Temporal
        profile.update_temporal(now)
        profile.total_events += 1

        # Data volume (if present)
        data_vol = p.get("unusual_data_volume_gb") or p.get("data_volume_gb")
        if data_vol is not None:
            profile.add_data_volume(float(data_vol))

        # Lateral movement (if we can infer destinations)
        # We look for dst_ip or destination
        dst = p.get("dst_ip") or p.get("destination")
        if dst:
            # For simplicity, track as a set of unique destinations per event
            # In production, you'd aggregate per session
            profile.add_lateral_destinations({str(dst)})

        # Application usage
        app = p.get("application") or p.get("process_name") or p.get("signature")
        if app:
            profile.add_app_usage(str(app))

        # After-hours index
        hour = now.hour
        # Business hours: 7-21
        is_off_hours = hour < 7 or hour > 21
        if is_off_hours:
            # Off-hours index: how far from business hours (0 at 7 or 21, 1 at midnight)
            if hour < 7:
                off_index = (7 - hour) / 7
            else:
                off_index = (hour - 21) / 3  # 21-24
            off_index = min(1.0, off_index)
        else:
            off_index = 0.0
        profile.add_after_hours_index(off_index)

        # Sensitive resource access
        resource = p.get("resource") or p.get("zone") or p.get("dst_port")
        if resource and str(resource) in self._config["sensitive_resources"]:
            profile.add_sensitive_access(1)

    def _update_profile_from_request(self, profile: BehavioralProfile, request: AccessRequest) -> None:
        """Update profile from access request."""
        # Temporal
        profile.update_temporal(request.timestamp)
        profile.total_events += 1

        # Resource
        if request.resource:
            profile.add_app_usage(request.resource)
            if request.resource in self._config["sensitive_resources"]:
                profile.add_sensitive_access(1)

        # After-hours
        hour = request.timestamp.hour
        is_off_hours = hour < 7 or hour > 21
        if is_off_hours:
            if hour < 7:
                off_index = (7 - hour) / 7
            else:
                off_index = (hour - 21) / 3
            off_index = min(1.0, off_index)
        else:
            off_index = 0.0
        profile.add_after_hours_index(off_index)

    # ============================================
    # Anomaly Detection
    # ============================================

    async def _check_anomalies(self, profile: BehavioralProfile, event: ThreatEvent) -> None:
        """Check if the current event triggers behavioral anomalies."""
        if not profile.is_stable:
            return

        # Compute individual anomaly scores for each signal
        anomaly_scores = {}
        reasons = []

        # 1. Login time (hour) — if we have enough history
        if len(profile.login_hours) > 5:
            # Check if current hour is unusual (not in typical hours)
            hour = event.timestamp.hour
            if hour not in profile.login_hours:
                # Compute deviation: how far from the typical hours?
                # For simplicity, if hour not in typical hours, add score
                deviation = 0.3  # base
                # Optionally, compute nearest typical hour distance
                nearest = min(abs(h - hour) for h in profile.login_hours) if profile.login_hours else 0
                if nearest > 3:
                    deviation = 0.6
                anomaly_scores["login_time"] = deviation
                reasons.append(f"Unusual login hour: {hour}")

        # 2. Data volume
        if profile.data_volume_gb:
            z = profile.get_z_score(profile.data_volume_gb[-1], "data_volume")
            if z > ANOMALY_Z_THRESHOLD:
                anomaly_scores["data_volume"] = min(1.0, z / 4.0)  # scale to 0-1
                reasons.append(f"Data volume spike: {profile.data_volume_gb[-1]:.1f}GB (Z={z:.2f})")

        # 3. Lateral movement
        if profile.lateral_destinations:
            # Use number of unique destinations in last event
            if profile.lateral_destinations:
                last_dests = profile.lateral_destinations[-1]
                count = len(last_dests)
                z = profile.get_z_score(count, "lateral")
                if z > ANOMALY_Z_THRESHOLD:
                    anomaly_scores["lateral_movement"] = min(1.0, z / 4.0)
                    reasons.append(f"Excessive lateral destinations: {count} (Z={z:.2f})")

        # 4. Email graph (if we have data)
        if profile.new_recipients_per_session:
            z = profile.get_z_score(profile.new_recipients_per_session[-1], "email")
            if z > ANOMALY_Z_THRESHOLD:
                anomaly_scores["email_graph"] = min(1.0, z / 4.0)
                reasons.append(f"Unusual new recipients: {profile.new_recipients_per_session[-1]} (Z={z:.2f})")

        # 5. Application usage sequence (if we have sequence)
        if len(profile.app_sequence) > 3:
            # Check if the current app is new or unusual compared to history
            current_app = profile.app_sequence[-1] if profile.app_sequence else None
            if current_app:
                # Compute frequency of this app in history
                total_apps = len(profile.app_sequence)
                freq = profile.app_usage_counts.get(current_app, 0) / total_apps if total_apps > 0 else 0
                if freq < 0.1:  # rare app
                    anomaly_scores["app_usage"] = 0.5
                    reasons.append(f"Rare application: {current_app} (freq={freq:.2f})")

        # 6. After-hours activity
        if profile.after_hours_index:
            z = profile.get_z_score(profile.after_hours_index[-1], "after_hours")
            if z > ANOMALY_Z_THRESHOLD:
                anomaly_scores["after_hours"] = min(1.0, z / 4.0)
                reasons.append(f"High after-hours activity index: {profile.after_hours_index[-1]:.2f} (Z={z:.2f})")

        # 7. Sensitive resource access
        if profile.sensitive_access_count:
            z = profile.get_z_score(profile.sensitive_access_count[-1], "sensitive")
            if z > ANOMALY_Z_THRESHOLD:
                anomaly_scores["sensitive_access"] = min(1.0, z / 4.0)
                reasons.append(f"Excessive sensitive resource access: {profile.sensitive_access_count[-1]} (Z={z:.2f})")

        # If no anomalies, return
        if not anomaly_scores:
            return

        # Compute overall anomaly score (weighted sum)
        total_score = 0.0
        total_weight = 0.0
        for signal, score in anomaly_scores.items():
            weight = self._config["signal_weights"].get(signal, 0.1)
            total_score += score * weight
            total_weight += weight
        if total_weight > 0:
            overall_score = total_score / total_weight
        else:
            overall_score = max(anomaly_scores.values()) if anomaly_scores else 0.0

        # Clamp to 0-1
        overall_score = min(1.0, overall_score)

        # Also consider peer group deviation (if user)
        peer_score = 0.0
        if profile.entity_type == "user":
            peer_score = self._compute_peer_anomaly(profile)
            overall_score = min(1.0, overall_score + peer_score * 0.3)  # blend

        # If overall score exceeds threshold, publish anomaly
        if overall_score > 0.4:  # configurable
            severity = self._score_to_severity(overall_score)
            payload = {
                "entity_id": profile.entity_id,
                "entity_type": profile.entity_type,
                "overall_anomaly_score": overall_score,
                "anomaly_signals": anomaly_scores,
                "reasons": reasons,
                "peer_deviation": peer_score,
                "original_event": {
                    "event_id": event.event_id,
                    "source": event.source,
                    "threat_type": event.threat_type.value,
                }
            }
            anomaly_event = ThreatEvent(
                source="UEBAEngine",
                threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                severity=severity,
                payload=payload,
                timestamp=event.timestamp
            )
            await self.bus.publish(anomaly_event)
            log.info(
                f"UEBA anomaly: {profile.entity_type} {profile.entity_id} "
                f"score={overall_score:.2f}, reasons={reasons[:3]}"
            )

    def _compute_peer_anomaly(self, profile: BehavioralProfile) -> float:
        """
        Compute how much the entity deviates from its peer group.
        Returns a score 0-1.
        """
        entity_id = profile.entity_id
        role = self._user_role.get(entity_id)
        if not role or role not in self._peer_groups:
            return 0.0

        peers = self._peer_groups[role]
        if not peers:
            return 0.0

        # Gather peer profiles
        peer_profiles = [self._profiles.get(p) for p in peers if p in self._profiles and p != entity_id]
        if len(peer_profiles) < 2:
            return 0.0

        # For simplicity, compare data volume average
        peer_volumes = [p.avg_data_volume_gb for p in peer_profiles if p.avg_data_volume_gb > 0]
        if not peer_volumes:
            return 0.0

        peer_mean = sum(peer_volumes) / len(peer_volumes)
        peer_std = math.sqrt(sum((v - peer_mean) ** 2 for v in peer_volumes) / len(peer_volumes)) if len(peer_volumes) > 1 else 0.0

        entity_vol = profile.avg_data_volume_gb
        if peer_std == 0:
            deviation = abs(entity_vol - peer_mean) / (peer_mean + 0.01)
        else:
            deviation = abs(entity_vol - peer_mean) / (peer_std + 0.01)

        # Cap at 1.0
        return min(1.0, deviation / self._config["peer_anomaly_z_threshold"])

    def _score_to_severity(self, score: float) -> Severity:
        """Map anomaly score to severity."""
        if score >= 0.8:
            return Severity.CRITICAL
        elif score >= 0.6:
            return Severity.HIGH
        elif score >= 0.4:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    # ============================================
    # Cleanup
    # ============================================

    async def _cleanup_loop(self) -> None:
        """Remove old profiles."""
        while self._running:
            await asyncio.sleep(3600)  # hourly
            try:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(seconds=self._config["profile_ttl_seconds"])
                expired = [eid for eid, p in self._profiles.items() if p.last_seen < cutoff]
                for eid in expired:
                    del self._profiles[eid]
                if expired:
                    log.debug(f"Removed {len(expired)} expired UEBA profiles")
            except Exception as e:
                log.error(f"UEBA cleanup error: {e}")

    def stop(self) -> None:
        """Stop the engine."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        log.info("UEBAEngine stopped")