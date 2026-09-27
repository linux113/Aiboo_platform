"""
engines/converged_events.py — Cyber‑Physical Convergence Event Models
# STATUS: Active. These models are imported by converged_security_engine.py
# and used throughout the Layer 3 Cyber‑Physical Convergence pipeline.
# Do NOT remove; they are not dead code.

Defines dedicated event types for physical presence, location updates,
and HR signals to support the Converged Security Decision Engine (CSDE).
These events are published by specialised adapters (e.g., badge readers,
CCTV systems, HRIS, MDM) and consumed by the CSDE to build entity histories.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List


# ============================================================
# Physical Presence Event
# ============================================================

@dataclass
class PhysicalPresenceEvent:
    """
    Represents a physical presence observation from any source:
    - Badge reader swipe
    - CCTV face recognition
    - Motion sensor trigger
    - GPS / Wi‑Fi location ping
    """
    entity_id: str                     # user ID, badge ID, or device ID
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # Location context
    zone: Optional[str] = None         # e.g., "server_room", "office_floor"
    location_name: Optional[str] = None  # human‑readable, "Mumbai Office"
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # Authentication details (if available)
    badge_id: Optional[str] = None
    badge_scan: bool = False
    face_match: bool = False
    face_match_confidence: float = 0.0

    # Motion / behaviour
    motion_score: float = 0.0
    tailgate_detected: bool = False
    loitering_detected: bool = False

    # Source system
    source: str = ""   # e.g., "badge_reader_12", "camera_03", "gps_mdm"

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_authenticated(self) -> bool:
        """True if either badge or face authentication succeeded."""
        return self.badge_scan or self.face_match


# ============================================================
# Location Update Event
# ============================================================

@dataclass
class LocationUpdateEvent:
    """
    Explicit location update from a mobile device (MDM), Wi‑Fi triangulation,
    or other geolocation service.
    """
    entity_id: str                     # user ID or device ID
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    latitude: float
    longitude: float
    accuracy_meters: Optional[float] = None
    location_name: Optional[str] = None   # reverse‑geocoded, "Office", "Home", "Coffee Shop"
    source: str = ""   # "mdm", "wifi", "gps"
    device_id: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# HR Event
# ============================================================

@dataclass
class HREvent:
    """
    Represents an event from the Human Resources system that may
    affect insider threat risk.
    """
    entity_id: str                     # employee ID (user_id)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    event_type: str   # "resignation", "performance_review_negative", "promotion",
                      # "leave_request", "complaint_filed", "role_change_sensitive"
    severity: str = "medium"  # "low", "medium", "high"
    description: str = ""
    source: str = ""   # "workday", "sap", "custom"
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Helper to map to weight (used in scoring)
    @property
    def risk_weight(self) -> float:
        """Return a numeric weight for scoring (0‑1)."""
        mapping = {
            "resignation": 0.5,
            "performance_review_negative": 0.3,
            "promotion": -0.2,
            "leave_request": 0.2,
            "complaint_filed": 0.4,
            "role_change_sensitive": 0.3,
            "performance_review_positive": -0.1,
            "termination_notice": 0.5,
        }
        return mapping.get(self.event_type, 0.0)


# ============================================================
# (Optional) Converged Alert – may be used instead of AgentFinding
# ============================================================

@dataclass
class ConvergedAlert:
    """
    Final alert from the CSDE, containing a unified risk score,
    story, and recommended actions. This is similar to AgentFinding
    but specifically for convergence alerts.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    entity_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    risk_score: int                     # 0‑1000
    risk_level: str                     # "low", "medium", "high", "critical"
    story: str
    actions: List[str]                  # ResponseAction values as strings

    # Which rule triggered the alert
    triggering_rule: str

    # Detailed breakdown
    contributing_signals: List[Dict[str, Any]] = field(default_factory=list)
    dimension_scores: Dict[str, float] = field(default_factory=dict)

    # Optional original event IDs that contributed
    related_event_ids: List[str] = field(default_factory=list)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_agent_finding(self):
        """Convert to an AgentFinding for compatibility with existing pipeline."""
        from core.events import AgentFinding, Severity, ThreatType, ResponseAction

        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        sev = severity_map.get(self.risk_level, Severity.MEDIUM)

        actions_enum = []
        for a in self.actions:
            try:
                actions_enum.append(ResponseAction(a))
            except ValueError:
                pass  # ignore unknown actions

        return AgentFinding(
            agent_name="ConvergedSecurityEngine",
            event_id=self.alert_id,
            threat_type=ThreatType.CORRELATED_ATTACK,
            severity=sev,
            confidence=min(1.0, self.risk_score / 1000),
            summary=self.story,
            actions=actions_enum,
            metadata={
                "entity_id": self.entity_id,
                "risk_score": self.risk_score,
                "triggering_rule": self.triggering_rule,
                "dimension_scores": self.dimension_scores,
                "contributing_signals": self.contributing_signals,
                "related_event_ids": self.related_event_ids,
                **self.metadata,
            }
        )