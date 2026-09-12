"""
engines/physical_security_engine.py — Physical Security & Cyber Correlation Engine

Correlates physical access events (badge swipes, CCTV, motion sensors) with
cyber events (network logins, access requests) to detect:

- Ghost logins: cyber access without physical presence
- Tailgating: unauthorized physical entry
- Zone access violations: entering restricted zones without proper authorization
- Physical-cyber mismatch: user logged in from an IP while their badge shows they're elsewhere

Enhanced for Layer 3 Cyber‑Physical Convergence – emits rich metadata
including entity_id, location details, badge info, and tailgate detection flags.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Tuple, Any

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity,
    AgentFinding, AccessRequest
)

log = logging.getLogger("PhysicalSecurityEngine")


def _ts_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

# ============================================
# Configuration Constants
# ============================================

# Time window for physical-cyber correlation (seconds)
PHYSICAL_CYBER_WINDOW = 1800  # 30 minutes

# Physical access cache size per user
MAX_PHYSICAL_EVENTS_PER_USER = 100

# Minimum confidence to consider a physical event as valid
MIN_PHYSICAL_CONFIDENCE = 0.6

# Restricted zones (from existing code)
RESTRICTED_ZONES = {"server_room", "server_room_anteroom", "data_vault", "executive_suite"}

# Critical zones (same as in surveillance_agent)
CRITICAL_ZONE_LEVEL = 3  # zones with level >= 3 are critical


@dataclass
class PhysicalAccessEvent:
    """Record of a physical access event."""
    user_id: str
    zone: str
    timestamp: datetime
    badge_scan: bool
    face_match: bool
    motion_score: float
    source: str  # "badge_reader", "camera", "motion_sensor"
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ---- NEW: Additional fields for CSDE ----
    badge_id: Optional[str] = None
    face_match_confidence: float = 0.0
    tailgate_detected: bool = False
    loitering_detected: bool = False


@dataclass
class CyberAccessEvent:
    """Record of a cyber access event (login, access request)."""
    user_id: str
    event_type: str  # "login", "access_request", "network_connection"
    resource: Optional[str] = None
    src_ip: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ---- NEW: Additional fields for CSDE ----
    location: Optional[str] = None
    detected_location: Optional[str] = None
    claimed_location: Optional[str] = None


class PhysicalSecurityEngine:
    """
    Physical Security & Cyber Correlation Engine.
    Maintains physical access history and correlates with cyber events.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._physical_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_PHYSICAL_EVENTS_PER_USER))  # user_id -> deque of PhysicalAccessEvent
        self._cyber_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_PHYSICAL_EVENTS_PER_USER))  # user_id -> deque of CyberAccessEvent
        self._running = False
        self._cleanup_task: Optional[asyncio.Task] = None

        # Configuration
        self._config = {
            "correlation_window_seconds": PHYSICAL_CYBER_WINDOW,
            "min_physical_confidence": MIN_PHYSICAL_CONFIDENCE,
            "restricted_zones": RESTRICTED_ZONES,
            "critical_zone_level": CRITICAL_ZONE_LEVEL,
            "zone_criticality": {  # from surveillance_agent
                "public_lobby": 0,
                "office_floor": 1,
                "restricted_corridor": 2,
                "server_room_anteroom": 3,
                "server_room": 4,
                "executive_suite": 3,
                "data_vault": 4,
            }
        }

        log.info("PhysicalSecurityEngine initialized")

    def start(self) -> None:
        """Start the engine: subscribe to events and start cleanup."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("PhysicalSecurityEngine started — correlating physical and cyber events")

    # ============================================
    # Event Handlers
    # ============================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events that contain physical context."""
        p = event.payload

        # If it's a physical intrusion event, treat it as a physical access event
        if event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            user_id = p.get("user_id") or p.get("entity_id")
            zone = p.get("zone")
            if not user_id or not zone:
                return

            # Extract physical access details
            badge_scan = bool(p.get("badge_scan", False))
            face_match = bool(p.get("face_match", False))
            motion_score = float(p.get("motion_anomaly_score", 0.0))

            # If this is from an agent finding, we might also get confidence from metadata
            confidence = float(p.get("confidence", 0.7))

            # ---- NEW: Extract additional fields ----
            badge_id = p.get("badge_id")
            face_match_confidence = float(p.get("face_match_confidence", 0.0))
            tailgate_detected = bool(p.get("tailgate_detected", False))
            loitering_detected = bool(p.get("loitering_detected", False))

            phys_event = PhysicalAccessEvent(
                user_id=user_id,
                zone=zone,
                timestamp=event.timestamp,
                badge_scan=badge_scan,
                face_match=face_match,
                motion_score=motion_score,
                source="surveillance_agent",
                confidence=confidence,
                metadata=p,
                # ---- NEW fields ----
                badge_id=badge_id,
                face_match_confidence=face_match_confidence,
                tailgate_detected=tailgate_detected,
                loitering_detected=loitering_detected,
            )
            self._physical_events[user_id].append(phys_event)

            # Also check for tailgating or other anomalies
            await self._check_physical_anomalies(phys_event, event)

        # Also check if the event contains any physical context (e.g., from other sources)
        if p.get("physical_context"):
            # Could be custom event with physical data
            user_id = p.get("user_id")
            zone = p.get("zone")
            if user_id and zone:
                phys_event = PhysicalAccessEvent(
                    user_id=user_id,
                    zone=zone,
                    timestamp=event.timestamp,
                    badge_scan=p.get("badge_scan", False),
                    face_match=p.get("face_match", False),
                    motion_score=p.get("motion_score", 0.0),
                    source="external",
                    confidence=p.get("confidence", 0.5),
                    metadata=p,
                    # ---- NEW fields ----
                    badge_id=p.get("badge_id"),
                    face_match_confidence=float(p.get("face_match_confidence", 0.0)),
                    tailgate_detected=bool(p.get("tailgate_detected", False)),
                    loitering_detected=bool(p.get("loitering_detected", False)),
                )
                self._physical_events[user_id].append(phys_event)

        # If the event is a network intrusion or identity event, treat as cyber event
        if event.threat_type in (ThreatType.NETWORK_INTRUSION, ThreatType.IDENTITY_MISMATCH):
            user_id = p.get("user_id")
            if not user_id:
                return

            # Extract location info for CSDE
            location = p.get("location") or p.get("detected_location") or p.get("claimed_location")
            detected_location = p.get("detected_location")
            claimed_location = p.get("claimed_location")

            # Create cyber event with enhanced fields
            cyber_event = CyberAccessEvent(
                user_id=user_id,
                event_type=event.threat_type.value,
                resource=p.get("resource") or p.get("signature"),
                src_ip=p.get("src_ip"),
                timestamp=event.timestamp,
                metadata=p,
                # ---- NEW fields ----
                location=location,
                detected_location=detected_location,
                claimed_location=claimed_location,
            )
            self._cyber_events[user_id].append(cyber_event)

            # Check correlation with physical events
            await self._correlate_physical_cyber(user_id, cyber_event, event)

    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests (cyber events)."""
        user_id = request.user_id
        if not user_id:
            return

        # Extract location info
        location = request.location

        # Create cyber event from request with enhanced fields
        cyber_event = CyberAccessEvent(
            user_id=user_id,
            event_type="access_request",
            resource=request.resource,
            src_ip=request.metadata.get("src_ip"),
            timestamp=request.timestamp,
            metadata={
                "location": request.location,
                "network": request.network,
                "behavior_context": request.behavior_context
            },
            # ---- NEW fields ----
            location=location,
            detected_location=location,
            claimed_location=location,
        )
        self._cyber_events[user_id].append(cyber_event)

        # Correlate
        await self._correlate_physical_cyber(user_id, cyber_event, None)

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings that may contain physical security info."""
        # If an agent reports a physical intrusion, we already handle via ThreatEvent
        # But we can also use findings to enrich physical events if needed
        # For example, if SurveillanceAgent finds a face match failure, we can use that.
        pass

    # ============================================
    # Correlation Logic
    # ============================================

    async def _correlate_physical_cyber(self, user_id: str, cyber_event: CyberAccessEvent, original_event: Optional[ThreatEvent]) -> None:
        """
        Correlate a cyber event with recent physical events for the same user.
        If no recent physical event is found, raise "ghost login" alert.
        """
        # Get recent physical events for this user within the correlation window
        physical_events = self._physical_events.get(user_id, [])
        if not physical_events:
            # No physical events at all for this user - ghost login (unless user is remote-only)
            # We'll treat as suspicious only if user is not known to be remote-only
            # For simplicity, we'll alert if there's no physical event and the cyber event is a login
            if cyber_event.event_type in ("login", "access_request", "network_intrusion"):
                # But we might want to check if this is a known remote user (not implemented)
                # For now, alert with medium severity
                await self._publish_physical_cyber_mismatch(
                    user_id, cyber_event, None,
                    reason="Cyber access without recent physical presence",
                    severity=Severity.HIGH
                )
            return

        # Find the most recent physical event within the correlation window
        now = datetime.now(timezone.utc)
        cutoff = cyber_event.timestamp - timedelta(seconds=self._config["correlation_window_seconds"])
        recent_physical = [e for e in physical_events if _ts_aware(e.timestamp) >= _ts_aware(cutoff) and e.confidence >= self._config["min_physical_confidence"]]

        if not recent_physical:
            # No physical event in window - ghost login
            # Check if the cyber event is a login or access to sensitive resource
            is_sensitive = False
            if cyber_event.resource:
                if any(zone in cyber_event.resource for zone in self._config["restricted_zones"]):
                    is_sensitive = True
            severity = Severity.CRITICAL if is_sensitive else Severity.HIGH

            await self._publish_physical_cyber_mismatch(
                user_id, cyber_event, None,
                reason=f"Cyber access without physical presence in the last {self._config['correlation_window_seconds']//60} minutes",
                severity=severity
            )
            return

        # If physical event exists, check if the zone matches (if available)
        # For example, if cyber event is for a specific zone/resource, check if the physical event is in the same zone
        # We can skip if we don't have zone info.

        # Also check if the physical event indicates unauthorized entry (face mismatch, no badge)
        latest_physical = recent_physical[-1]
        if not latest_physical.badge_scan or not latest_physical.face_match:
            # Physical access was not properly authenticated, but cyber access occurred shortly after
            # This could be tailgating or impersonation
            await self._publish_physical_cyber_mismatch(
                user_id, cyber_event, latest_physical,
                reason=f"Cyber access followed by physical access with authentication failure (badge={latest_physical.badge_scan}, face={latest_physical.face_match})",
                severity=Severity.HIGH
            )

    async def _check_physical_anomalies(self, phys_event: PhysicalAccessEvent, original_event: ThreatEvent) -> None:
        """
        Detect anomalies purely from physical events (tailgating, unauthorized zone access).
        """
        # Zone criticality
        zone_level = self._config["zone_criticality"].get(phys_event.zone, 0)

        # If restricted zone and authentication failure
        if phys_event.zone in self._config["restricted_zones"]:
            if not phys_event.badge_scan or not phys_event.face_match:
                # Unauthorized access to restricted zone
                severity = Severity.CRITICAL if zone_level >= 3 else Severity.HIGH
                await self._publish_physical_anomaly(
                    phys_event,
                    reason=f"Unauthorized access to restricted zone {phys_event.zone} (badge={phys_event.badge_scan}, face={phys_event.face_match})",
                    severity=severity
                )

        # If motion score high and no badge/face, could be intrusion
        if phys_event.motion_score > 0.85 and not phys_event.badge_scan and not phys_event.face_match:
            await self._publish_physical_anomaly(
                phys_event,
                reason=f"High motion anomaly ({phys_event.motion_score:.2f}) with no authentication in {phys_event.zone}",
                severity=Severity.CRITICAL if zone_level >= 3 else Severity.HIGH
            )

        # ---- NEW: Tailgating detection (explicit flag from CCTV) ----
        if phys_event.tailgate_detected:
            # If tailgating is explicitly detected by CCTV
            severity = Severity.CRITICAL if zone_level >= 3 else Severity.HIGH
            await self._publish_physical_anomaly(
                phys_event,
                reason=f"Tailgating detected in {phys_event.zone} by CCTV",
                severity=severity,
                tailgate=True
            )

    # ============================================
    # Publishing Alerts
    # ============================================

    async def _publish_physical_cyber_mismatch(self, user_id: str, cyber_event: CyberAccessEvent,
                                               phys_event: Optional[PhysicalAccessEvent],
                                               reason: str, severity: Severity) -> None:
        """Publish a physical-cyber mismatch alert with CSDE-friendly fields."""
        payload = {
            "user_id": user_id,
            "entity_id": user_id,  # alias for CSDE
            "cyber_event": {
                "event_type": cyber_event.event_type,
                "resource": cyber_event.resource,
                "src_ip": cyber_event.src_ip,
                "timestamp": cyber_event.timestamp.isoformat(),
                "location": cyber_event.location,
                "detected_location": cyber_event.detected_location,
                "claimed_location": cyber_event.claimed_location,
            },
            "physical_event": None,
            "reason": reason,
            "mismatch_type": "ghost_login" if phys_event is None else "auth_failure",
            # ---- NEW: flags for CSDE ----
            "ghost_login_detected": phys_event is None,
            "tailgating_detected": False,
            "physical_cyber_mismatch": True,
        }
        if phys_event:
            payload["physical_event"] = {
                "zone": phys_event.zone,
                "badge_scan": phys_event.badge_scan,
                "face_match": phys_event.face_match,
                "motion_score": phys_event.motion_score,
                "timestamp": phys_event.timestamp.isoformat(),
                "confidence": phys_event.confidence,
                # ---- NEW fields ----
                "badge_id": phys_event.badge_id,
                "face_match_confidence": phys_event.face_match_confidence,
                "tailgate_detected": phys_event.tailgate_detected,
                "loitering_detected": phys_event.loitering_detected,
            }

        alert_event = ThreatEvent(
            source="PhysicalSecurityEngine",
            threat_type=ThreatType.PHYSICAL_CYBER_MISMATCH,  # Use specific type for CSDE
            severity=severity,
            payload=payload,
            timestamp=datetime.now(timezone.utc)
        )
        await self.bus.publish(alert_event)
        log.warning(f"Physical-cyber mismatch: {user_id} - {reason} (severity={severity.value})")

    async def _publish_physical_anomaly(self, phys_event: PhysicalAccessEvent, reason: str, severity: Severity,
                                        tailgate: bool = False) -> None:
        """Publish a physical anomaly alert with CSDE-friendly fields."""
        payload = {
            "user_id": phys_event.user_id,
            "entity_id": phys_event.user_id,  # alias for CSDE
            "zone": phys_event.zone,
            "badge_scan": phys_event.badge_scan,
            "face_match": phys_event.face_match,
            "motion_score": phys_event.motion_score,
            "timestamp": phys_event.timestamp.isoformat(),
            "reason": reason,
            "source": phys_event.source,
            # ---- NEW fields ----
            "badge_id": phys_event.badge_id,
            "face_match_confidence": phys_event.face_match_confidence,
            "tailgate_detected": phys_event.tailgate_detected or tailgate,
            "loitering_detected": phys_event.loitering_detected,
            # ---- flags for CSDE ----
            "ghost_login_detected": False,
            "physical_cyber_mismatch": False,
            "tailgating_detected": phys_event.tailgate_detected or tailgate,
        }

        alert_event = ThreatEvent(
            source="PhysicalSecurityEngine",
            threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=severity,
            payload=payload,
            timestamp=datetime.now(timezone.utc)
        )
        await self.bus.publish(alert_event)
        log.warning(f"Physical anomaly: {phys_event.user_id} in {phys_event.zone} - {reason} (severity={severity.value})")

    # ============================================
    # Cleanup
    # ============================================

    async def _cleanup_loop(self) -> None:
        """Periodically clean old events to free memory."""
        while self._running:
            await asyncio.sleep(3600)  # hourly
            try:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(hours=24)  # keep last 24 hours

                # Clean physical events
                for user_id in list(self._physical_events.keys()):
                    events = self._physical_events[user_id]
                    # deque will automatically discard old items due to maxlen, but we can also filter
                    # Since we use deque(maxlen=MAX), we don't need to filter here

                # Clean cyber events similarly
                for user_id in list(self._cyber_events.keys()):
                    events = self._cyber_events[user_id]
                    # Already limited by maxlen

                # Remove empty users
                for user_id in list(self._physical_events.keys()):
                    if not self._physical_events[user_id]:
                        del self._physical_events[user_id]
                for user_id in list(self._cyber_events.keys()):
                    if not self._cyber_events[user_id]:
                        del self._cyber_events[user_id]

            except Exception as e:
                log.error(f"PhysicalSecurityEngine cleanup error: {e}")

    def stop(self) -> None:
        """Stop the engine."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        log.info("PhysicalSecurityEngine stopped")

    # ============================================
    # Public Query Methods
    # ============================================

    def get_recent_physical_events(self, user_id: str, limit: int = 10) -> List[PhysicalAccessEvent]:
        """Get recent physical events for a user."""
        events = self._physical_events.get(user_id, [])
        return list(events)[-limit:]

    def get_recent_cyber_events(self, user_id: str, limit: int = 10) -> List[CyberAccessEvent]:
        """Get recent cyber events for a user."""
        events = self._cyber_events.get(user_id, [])
        return list(events)[-limit:]