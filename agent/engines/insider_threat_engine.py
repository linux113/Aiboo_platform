"""
engines/insider_threat_engine.py — Insider Threat Scoring Engine

Computes a composite Insider Risk Score for every user based on:

1. Behavioral Deviation Score (from UEBA)
2. Data Exfiltration Risk (from DLP-like signals)
3. HR Signals (performance, leave, termination notices)
4. Physical Anomaly Score (from Physical Security Engine)
5. Peer Comparison Score (from UEBA peer analysis)

Publishes ThreatEvent when score exceeds configurable thresholds.

Enhanced for Layer 3 Cyber‑Physical Convergence – emits rich dimension
scores, HR details, and entity identifiers for the Converged Security Engine.
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Tuple, Any
from collections import defaultdict, deque

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity,
    AgentFinding, AccessRequest
)

log = logging.getLogger("InsiderThreatEngine")

# ============================================
# Configuration Constants
# ============================================

# Default weights for each risk dimension
DEFAULT_WEIGHTS = {
    "behavioral": 0.30,      # from UEBA
    "data_exfil": 0.25,      # data exfiltration signals
    "hr_signal": 0.15,       # HR events (performance, leave, termination)
    "physical": 0.15,        # physical anomalies
    "peer_compare": 0.15,    # deviation from peers
}

# Score thresholds
RISK_THRESHOLDS = {
    "low": 300,      # 0-300: low risk (passive monitoring)
    "medium": 450,   # 301-450: medium risk (enhanced verification)
    "high": 650,     # 451-650: high risk (alert, SOC notified)
    "critical": 800, # 651-800: critical (automated containment)
    "severe": 951,   # 801-1000: severe (full response)
}

# HR event types and their weights
HR_EVENT_WEIGHTS = {
    "performance_review_negative": 0.3,
    "performance_review_positive": -0.1,
    "termination_notice": 0.5,
    "leave_request": 0.2,
    "complaint_filed": 0.4,
    "promotion": -0.2,
    "role_change_sensitive": 0.3,
}

# Data exfiltration indicators
EXFIL_INDICATORS = {
    "large_data_download": 0.3,
    "email_to_personal": 0.4,
    "usb_attachment": 0.3,
    "cloud_upload": 0.2,
    "sensitive_file_access": 0.3,
    "encrypted_archive_creation": 0.4,
}

# Decay rate per day (score reduces over time if no new signals)
DAILY_DECAY = 0.03  # 3% per day

# History retention (in events)
MAX_HISTORY_PER_USER = 200

# Minimum events to establish baseline
MIN_EVENTS_FOR_SCORE = 5


@dataclass
class InsiderRiskRecord:
    """Complete risk record for a user."""
    user_id: str

    # Dimension scores (0-1, aggregated)
    behavioral_score: float = 0.0
    data_exfil_score: float = 0.0
    hr_signal_score: float = 0.0
    physical_score: float = 0.0
    peer_compare_score: float = 0.0

    # Overall score (0-1000)
    overall_score: float = 0.0

    # Raw signal history (recent events)
    raw_signals: List[Dict[str, Any]] = field(default_factory=list)

    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_decay: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Counters
    event_count: int = 0
    high_severity_events: int = 0

    # Flags
    is_high_risk: bool = False
    is_monitoring: bool = False  # silent monitoring mode (enhanced logging)
    mitigation_applied: bool = False

    def update_dimension(self, dim: str, value: float):
        """Update a specific dimension score (0-1)."""
        setattr(self, dim, min(1.0, max(0.0, value)))
        self.last_updated = datetime.now(timezone.utc)
        self._recalculate_overall()

    def _recalculate_overall(self):
        """Recalculate overall score from weighted dimensions."""
        total = 0.0
        for dim, weight in DEFAULT_WEIGHTS.items():
            score = getattr(self, dim, 0.0)
            total += score * weight
        # Convert to 0-1000 scale
        self.overall_score = total * 1000
        self.last_updated = datetime.now(timezone.utc)

    def apply_decay(self, days: float):
        """Apply time decay to all scores."""
        decay_factor = 1 - (DAILY_DECAY * days)
        if decay_factor < 0:
            decay_factor = 0
        self.behavioral_score *= decay_factor
        self.data_exfil_score *= decay_factor
        self.hr_signal_score *= decay_factor
        self.physical_score *= decay_factor
        self.peer_compare_score *= decay_factor
        self.last_decay = datetime.now(timezone.utc)
        self._recalculate_overall()

    def add_signal(self, signal: Dict[str, Any]):
        """Add a raw signal event to history."""
        self.raw_signals.append(signal)
        if len(self.raw_signals) > MAX_HISTORY_PER_USER:
            self.raw_signals = self.raw_signals[-MAX_HISTORY_PER_USER:]
        self.event_count += 1

    def get_risk_level(self) -> str:
        """Get risk level string based on overall score."""
        score = self.overall_score
        if score >= RISK_THRESHOLDS["severe"]:
            return "severe"
        elif score >= RISK_THRESHOLDS["critical"]:
            return "critical"
        elif score >= RISK_THRESHOLDS["high"]:
            return "high"
        elif score >= RISK_THRESHOLDS["medium"]:
            return "medium"
        else:
            return "low"

    def get_risk_severity(self) -> Severity:
        """Get severity for alerts."""
        level = self.get_risk_level()
        mapping = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
            "severe": Severity.CRITICAL,
        }
        return mapping.get(level, Severity.MEDIUM)


class InsiderThreatEngine:
    """
    Insider Threat Scoring Engine.
    Maintains risk records for users, updates dimensions from various sources,
    and publishes alerts when risk exceeds thresholds.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._records: Dict[str, InsiderRiskRecord] = {}
        self._running = False

        # Background tasks
        self._decay_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None

        # Configuration
        self._config = {
            "weights": DEFAULT_WEIGHTS.copy(),
            "thresholds": RISK_THRESHOLDS.copy(),
            "daily_decay": DAILY_DECAY,
            "alert_cooldown_seconds": 3600,  # avoid spamming same user
        }

        # Cooldown tracking (last alert time per user)
        self._last_alert_time: Dict[str, datetime] = {}

        log.info("InsiderThreatEngine initialized")

    def start(self) -> None:
        """Start the engine: subscribe to events and start background tasks."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._decay_task = asyncio.create_task(self._decay_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("InsiderThreatEngine started")

    # ============================================
    # Event Handlers
    # ============================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events to update scores."""
        p = event.payload

        # Extract user_id (prefer user_id, fallback to entity_id)
        user_id = p.get("user_id")
        if not user_id:
            user_id = p.get("entity_id") or p.get("src_user")
        if not user_id:
            return

        record = self._get_or_create_record(user_id)
        updated = False

        # Keep track of HR signal details for CSDE
        hr_event_type = None
        hr_event_description = None

        # 1. Behavioral anomalies (from UEBA)
        if event.threat_type == ThreatType.ANOMALOUS_BEHAVIOR:
            anomaly_score = float(p.get("overall_anomaly_score", 0.0))
            if anomaly_score > 0:
                record.behavioral_score = min(1.0, record.behavioral_score + anomaly_score * 0.2)
                updated = True

        # 2. Data exfiltration signals
        if event.threat_type == ThreatType.INSIDER_THREAT:
            # If already an insider threat event, update data_exfil
            exfil_score = float(p.get("exfil_risk", 0.0))
            if exfil_score > 0:
                record.data_exfil_score = min(1.0, record.data_exfil_score + exfil_score * 0.3)
                updated = True

        # Also check payload for data exfiltration indicators
        data_vol = p.get("unusual_data_volume_gb") or p.get("data_volume_gb")
        if data_vol:
            # Large data volume is a strong signal
            if data_vol > 10:  # GB
                record.data_exfil_score = min(1.0, record.data_exfil_score + 0.2)
                updated = True
            elif data_vol > 5:
                record.data_exfil_score = min(1.0, record.data_exfil_score + 0.1)
                updated = True

        # 3. Physical anomalies (from physical security engine)
        if event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            if p.get("zone"):
                record.physical_score = min(1.0, record.physical_score + 0.15)
                updated = True

        # 4. HR signals (from metadata)
        hr_signal = p.get("hr_signal")
        if hr_signal and hr_signal in HR_EVENT_WEIGHTS:
            weight = HR_EVENT_WEIGHTS[hr_signal]
            hr_event_type = hr_signal
            hr_event_description = p.get("hr_description", hr_signal)
            # Convert weight to score adjustment (0-1 range)
            if weight > 0:
                record.hr_signal_score = min(1.0, record.hr_signal_score + weight * 0.3)
            else:
                # Negative signal reduces score (e.g., positive performance review)
                record.hr_signal_score = max(0.0, record.hr_signal_score + weight * 0.3)
            updated = True

        # Also check for explicit HREvent in payload (if someone publishes via core.converged_events)
        if p.get("hr_event_type"):
            hr_event_type = p.get("hr_event_type")
            hr_event_description = p.get("hr_description") or p.get("description", hr_event_type)
            weight = HR_EVENT_WEIGHTS.get(hr_event_type, 0.3)
            if weight > 0:
                record.hr_signal_score = min(1.0, record.hr_signal_score + weight * 0.3)
            else:
                record.hr_signal_score = max(0.0, record.hr_signal_score + weight * 0.3)
            updated = True

        # 5. Peer comparison updates (if available)
        peer_dev = p.get("peer_deviation")
        if peer_dev is not None:
            record.peer_compare_score = min(1.0, record.peer_compare_score + peer_dev * 0.3)
            updated = True

        if updated:
            record._recalculate_overall()
            # Store HR context for CSDE if available
            if hr_event_type:
                record.add_signal({
                    "timestamp": event.timestamp.isoformat(),
                    "hr_event_type": hr_event_type,
                    "hr_event_description": hr_event_description,
                    "dimension": "hr_signal",
                    "score": record.hr_signal_score,
                })
            await self._check_and_alert(record, event, hr_event_type, hr_event_description)

    async def _on_access_request(self, request: AccessRequest) -> None:
        """Process access requests for additional signals."""
        user_id = request.user_id
        record = self._get_or_create_record(user_id)

        # Check if accessing sensitive resources
        sensitive = set(["database", "server_room", "data_vault", "admin_console"])
        if request.resource in sensitive:
            # Increased data exfil risk if accessing sensitive resources
            record.data_exfil_score = min(1.0, record.data_exfil_score + 0.05)
            record._recalculate_overall()
            await self._check_and_alert(record, None)

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings (e.g., high-confidence threats)."""
        user_id = finding.metadata.get("user_id")
        if not user_id:
            return

        record = self._get_or_create_record(user_id)

        # If an agent confirms a threat, increase relevant scores
        if finding.severity == Severity.CRITICAL and finding.confidence > 0.8:
            record.behavioral_score = min(1.0, record.behavioral_score + 0.3)
            record._recalculate_overall()
            await self._check_and_alert(record, None)

    # ============================================
    # Core Scoring & Alerting
    # ============================================

    def _get_or_create_record(self, user_id: str) -> InsiderRiskRecord:
        """Get existing record or create a new one."""
        if user_id in self._records:
            return self._records[user_id]

        record = InsiderRiskRecord(user_id=user_id)
        self._records[user_id] = record
        log.debug(f"Created insider threat record for {user_id}")
        return record

    async def _check_and_alert(self, record: InsiderRiskRecord, original_event: Optional[ThreatEvent],
                               hr_event_type: Optional[str] = None,
                               hr_event_description: Optional[str] = None) -> None:
        """
        Check if risk level warrants alert and publish if needed.
        Uses cooldown to avoid spamming.
        """
        score = record.overall_score
        level = record.get_risk_level()
        severity = record.get_risk_severity()

        # Determine if alert is needed (medium or higher)
        if level == "low":
            return

        # Cooldown: don't alert more than once per hour per user
        now = datetime.now(timezone.utc)
        last_alert = self._last_alert_time.get(record.user_id)
        if last_alert and (now - last_alert).total_seconds() < self._config["alert_cooldown_seconds"]:
            return

        # Update last alert time
        self._last_alert_time[record.user_id] = now

        # Build dimension breakdown for CSDE
        dimension_breakdown = {
            "behavioral": {
                "score": record.behavioral_score,
                "weight": self._config["weights"]["behavioral"],
                "contribution": record.behavioral_score * self._config["weights"]["behavioral"],
            },
            "data_exfil": {
                "score": record.data_exfil_score,
                "weight": self._config["weights"]["data_exfil"],
                "contribution": record.data_exfil_score * self._config["weights"]["data_exfil"],
            },
            "hr_signal": {
                "score": record.hr_signal_score,
                "weight": self._config["weights"]["hr_signal"],
                "contribution": record.hr_signal_score * self._config["weights"]["hr_signal"],
                "hr_event_type": hr_event_type,
                "hr_event_description": hr_event_description,
            },
            "physical": {
                "score": record.physical_score,
                "weight": self._config["weights"]["physical"],
                "contribution": record.physical_score * self._config["weights"]["physical"],
            },
            "peer_compare": {
                "score": record.peer_compare_score,
                "weight": self._config["weights"]["peer_compare"],
                "contribution": record.peer_compare_score * self._config["weights"]["peer_compare"],
            },
        }

        # Build detailed payload with explicit CSDE-friendly fields
        payload = {
            "user_id": record.user_id,
            "entity_id": record.user_id,          # for CSDE correlation
            "overall_score": score,
            "risk_level": level,
            "severity": severity.value,
            "dimension_scores": {
                "behavioral": record.behavioral_score,
                "data_exfil": record.data_exfil_score,
                "hr_signal": record.hr_signal_score,
                "physical": record.physical_score,
                "peer_compare": record.peer_compare_score,
            },
            "dimension_weights": self._config["weights"],
            "dimension_breakdown": dimension_breakdown,  # detailed for CSDE
            "recent_signals": record.raw_signals[-5:],   # last 5 signals
            "event_count": record.event_count,
            "mitigation_applied": record.mitigation_applied,
            "is_monitoring": record.is_monitoring,
            "original_event": {
                "event_id": original_event.event_id if original_event else None,
                "source": original_event.source if original_event else None,
                "threat_type": original_event.threat_type.value if original_event else None,
            } if original_event else None,
            # CSDE‑specific fields
            "hr_event_type": hr_event_type,
            "hr_event_description": hr_event_description,
        }

        # Publish as ThreatEvent
        alert_event = ThreatEvent(
            source="InsiderThreatEngine",
            threat_type=ThreatType.INSIDER_THREAT,
            severity=severity,
            payload=payload,
            timestamp=datetime.now(timezone.utc)
        )
        await self.bus.publish(alert_event)

        log.warning(
            f"Insider threat alert: {record.user_id} score={score:.1f} level={level} "
            f"behavioral={record.behavioral_score:.2f} data_exfil={record.data_exfil_score:.2f} "
            f"hr={record.hr_signal_score:.2f} physical={record.physical_score:.2f} peer={record.peer_compare_score:.2f}"
        )

        # If critical or severe, automatically enable silent monitoring mode
        if level in ("critical", "severe"):
            record.is_monitoring = True
            log.info(f"Silent monitoring enabled for {record.user_id}")

    # ============================================
    # Background Decay & Cleanup
    # ============================================

    async def _decay_loop(self) -> None:
        """Periodically apply time decay to all scores."""
        while self._running:
            await asyncio.sleep(3600)  # hourly
            try:
                for record in self._records.values():
                    # Apply decay
                    days = 1  # since last decay (simplified)
                    record.apply_decay(days)
                    # If score drops below low threshold, turn off monitoring
                    if record.overall_score < RISK_THRESHOLDS["medium"] and record.is_monitoring:
                        record.is_monitoring = False
                        log.debug(f"Monitoring disabled for {record.user_id} (score dropped)")
            except Exception as e:
                log.error(f"Decay loop error: {e}")

    async def _cleanup_loop(self) -> None:
        """Remove old records that haven't been updated in a while."""
        while self._running:
            await asyncio.sleep(86400)  # daily
            try:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(days=90)  # keep 90 days
                to_delete = []
                for user_id, record in self._records.items():
                    if record.last_updated < cutoff and record.overall_score < 100:
                        to_delete.append(user_id)
                for user_id in to_delete:
                    del self._records[user_id]
                    log.debug(f"Removed stale insider record for {user_id}")
            except Exception as e:
                log.error(f"Cleanup loop error: {e}")

    # ============================================
    # Public Query Methods
    # ============================================

    def get_record(self, user_id: str) -> Optional[InsiderRiskRecord]:
        """Get risk record for a user."""
        return self._records.get(user_id)

    def get_high_risk_users(self, min_score: float = 450) -> List[Tuple[str, float]]:
        """Get users with score >= min_score."""
        return [(uid, rec.overall_score) for uid, rec in self._records.items() if rec.overall_score >= min_score]

    def enable_silent_monitoring(self, user_id: str) -> bool:
        """Manually enable silent monitoring for a user."""
        record = self._records.get(user_id)
        if record:
            record.is_monitoring = True
            return True
        return False

    def disable_silent_monitoring(self, user_id: str) -> bool:
        """Manually disable silent monitoring."""
        record = self._records.get(user_id)
        if record:
            record.is_monitoring = False
            return True
        return False

    def apply_mitigation(self, user_id: str, mitigation: str) -> bool:
        """Record that mitigation was applied (e.g., access restrictions)."""
        record = self._records.get(user_id)
        if record:
            record.mitigation_applied = True
            # Optionally, reduce scores after mitigation
            record.data_exfil_score *= 0.5
            record.behavioral_score *= 0.7
            record._recalculate_overall()
            return True
        return False

    # ============================================
    # Shutdown
    # ============================================

    def stop(self) -> None:
        """Stop the engine."""
        self._running = False
        if self._decay_task:
            self._decay_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        log.info("InsiderThreatEngine stopped")