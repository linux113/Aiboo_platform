"""
engines/converged_security_engine.py — Converged Security Decision Engine (CSDE)

Cyber‑Physical Convergence engine that:
- Maintains per‑entity historical signal buffer (last 7 days)
- Evaluates four convergence rules:
  1. Ghost Login – login location contradicts physical presence
  2. Invisible Insider – multi‑day low‑level anomalies + HR trigger
  3. Tailgating – badge mismatch + CCTV detection
  4. Ransomware Prelude – DNS anomalies + lateral movement + reconnaissance + off‑hours VPN

Produces a unified risk score (0‑1000) and publishes AgentFinding with recommended actions.

Part of Layer 3: Adaptive Cyber‑Physical Response.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple

from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity, ThreatEvent, ThreatType,
    AccessRequest, RiskLevel,
)

log = logging.getLogger("ConvergedSecurityEngine")

# ============================================================
# Configuration (hardcoded for now; could be YAML)
# ============================================================
MAX_HISTORY_DAYS = 7
EVALUATION_INTERVAL_SECONDS = 60  # run every minute
SCORE_THRESHOLD_GHOST_LOGIN = 800
SCORE_THRESHOLD_INSIDER = 750
SCORE_THRESHOLD_TAILGATING = 850
SCORE_THRESHOLD_RANSOMWARE = 800

# Time windows
GHOST_LOGIN_WINDOW_HOURS = 12      # look back for physical presence
INSIDER_WINDOW_HOURS = 72          # 3 days
TAILGATING_WINDOW_MINUTES = 5      # badge + CCTV within 5 min
RANSOMWARE_WINDOW_HOURS = 6        # 6‑hour window for sequence

# Cooldown to prevent duplicate alerts (seconds)
ALERT_COOLDOWN_SECONDS = 3600      # 1 hour

# Weights for each contributing factor (simplified)
# (Used in scoring functions; could be externalized)
DEFAULT_WEIGHTS = {
    "ghost_login": {"location_contradiction": 0.6, "geo_velocity": 0.4},
    "insider": {
        "data_volume": 0.25,
        "unusual_access": 0.20,
        "physical_after_hours": 0.15,
        "email_exfil": 0.20,
        "hr_resignation": 0.20,
    },
    "tailgating": {"badge_mismatch": 0.5, "cctv_tailgate": 0.5},
    "ransomware": {
        "dns_anomaly": 0.20,
        "lateral_movement": 0.30,
        "reconnaissance": 0.20,
        "off_hours_vpn": 0.30,
    },
}

# ============================================================
# Data Structures
# ============================================================

class SignalType:
    """Enumeration of signal categories for internal use."""
    LOGIN = "login"
    PHYSICAL_ACCESS = "physical_access"
    CCTV = "cctv"
    DEVICE_ACTIVITY = "device_activity"
    NETWORK_BEHAVIOR = "network_behavior"
    HR_EVENT = "hr_event"
    ACCESS_REQUEST = "access_request"
    ANOMALY = "anomaly"
    LOCATION_UPDATE = "location_update"


@dataclass
class Signal:
    """Normalized signal record for an entity."""
    timestamp: datetime
    signal_type: str            # one of SignalType values
    domain: str                 # "physical", "cyber", "hr"
    entity_id: str              # user, device, IP
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Common fields:
    #   location: str (optional)
    #   ip: str (optional)
    #   badge_id: str (optional)
    #   zone: str (optional)
    #   data_volume_gb: float (optional)
    #   resource: str (optional)
    #   process_name: str (optional)
    #   event_id: str (original event ID)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "signal_type": self.signal_type,
            "domain": self.domain,
            "entity_id": self.entity_id,
            "metadata": self.metadata,
        }


class EntityHistory:
    """Tracks recent signals for a single entity."""
    def __init__(self, entity_id: str):
        self.entity_id = entity_id
        self.signals: deque = deque()  # of Signal, sorted chronologically
        self.last_evaluation: Optional[datetime] = None

    @staticmethod
    def _ts(dt: datetime) -> datetime:
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

    def add_signal(self, signal: Signal) -> None:
        """Add a signal, prune old ones (> MAX_HISTORY_DAYS)."""
        self.signals.append(signal)
        cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_HISTORY_DAYS)
        while self.signals and self._ts(self.signals[0].timestamp) < cutoff:
            self.signals.popleft()

    def get_signals_since(self, since: datetime) -> List[Signal]:
        """Return signals with timestamp >= since."""
        result = []
        since_aware = self._ts(since)
        for s in reversed(self.signals):
            if self._ts(s.timestamp) >= since_aware:
                result.append(s)
            else:
                break  # since deque is sorted
        return result

    def get_signals_by_type(self, signal_type: str, since: Optional[datetime] = None) -> List[Signal]:
        """Filter signals by type and optional time window."""
        if since is None:
            since = datetime.min.replace(tzinfo=timezone.utc)
        since_aware = self._ts(since)
        return [s for s in self.signals if s.signal_type == signal_type and self._ts(s.timestamp) >= since_aware]

    def get_latest_signal_of_type(self, signal_type: str) -> Optional[Signal]:
        """Return the most recent signal of a given type, or None."""
        for s in reversed(self.signals):
            if s.signal_type == signal_type:
                return s
        return None


# ============================================================
# Main Engine Class
# ============================================================

class ConvergedSecurityEngine:
    """
    Cyber‑Physical Convergence Engine.
    Subscribes to events, builds entity histories, runs rule evaluations,
    and publishes unified risk alerts.
    """
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._histories: Dict[str, EntityHistory] = {}
        self._running = False
        self._evaluation_task: Optional[asyncio.Task] = None

        # Cooldown cache to prevent duplicate alerts
        self._last_alert_time: Dict[str, datetime] = {}
        self._alert_cooldown_seconds = ALERT_COOLDOWN_SECONDS

    def start(self) -> None:
        """Subscribe to relevant events and start background evaluation."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._evaluation_task = asyncio.create_task(self._evaluation_loop())
        log.info("ConvergedSecurityEngine started — monitoring cyber‑physical convergence.")

    async def stop(self) -> None:
        """Stop the engine and cancel background tasks."""
        self._running = False
        if self._evaluation_task:
            self._evaluation_task.cancel()
        log.info("ConvergedSecurityEngine stopped.")

    # ============================================================
    # Event Handlers
    # ============================================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Convert ThreatEvent to a normalized Signal and store."""
        signal = self._threat_event_to_signal(event)
        if signal:
            self._get_history(signal.entity_id).add_signal(signal)
            # Optionally trigger immediate evaluation for high‑severity events?
            # We rely on periodic evaluation.

    async def _on_access_request(self, request: AccessRequest) -> None:
        """Convert AccessRequest to a Signal and store."""
        signal = self._access_request_to_signal(request)
        if signal:
            self._get_history(signal.entity_id).add_signal(signal)

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """
        Agent findings (e.g., from InsiderThreatEngine, PhysicalSecurityEngine)
        are themselves high‑level signals. We store them as ANOMALY signals.
        """
        # Extract entity from finding metadata
        entity_id = finding.metadata.get("entity_id") or finding.metadata.get("user_id") or finding.metadata.get("src_ip")
        if not entity_id:
            return
        signal = Signal(
            timestamp=finding.timestamp,
            signal_type=SignalType.ANOMALY,
            domain="cyber" if "cyber" in finding.agent_name.lower() else "physical",
            entity_id=entity_id,
            metadata={
                "agent_name": finding.agent_name,
                "threat_type": finding.threat_type.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "summary": finding.summary,
                "actions": [a.value for a in finding.actions],
                "original_finding": finding.metadata,
            }
        )
        self._get_history(entity_id).add_signal(signal)

    # ============================================================
    # Signal Conversion
    # ============================================================

    def _threat_event_to_signal(self, event: ThreatEvent) -> Optional[Signal]:
        """Convert ThreatEvent to a normalized Signal."""
        p = event.payload
        entity_id = p.get("user_id") or p.get("src_ip") or p.get("device_id")
        if not entity_id:
            return None

        # Determine signal type and domain based on ThreatType
        signal_type = None
        domain = "cyber"
        metadata = {
            "event_id": event.event_id,
            "source": event.source,
            "severity": event.severity.value,
            "threat_type": event.threat_type.value,
            **p,
        }

        if event.threat_type == ThreatType.IDENTITY_MISMATCH:
            signal_type = SignalType.LOGIN
            domain = "cyber"
            # Extract location
            metadata["location"] = p.get("detected_location") or p.get("claimed_location")
            metadata["ip"] = p.get("src_ip")
        elif event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            signal_type = SignalType.PHYSICAL_ACCESS
            domain = "physical"
            metadata["zone"] = p.get("zone")
            metadata["badge_scan"] = p.get("badge_scan")
            metadata["face_match"] = p.get("face_match")
            metadata["motion_score"] = p.get("motion_anomaly_score")
        elif event.threat_type == ThreatType.NETWORK_INTRUSION:
            signal_type = SignalType.NETWORK_BEHAVIOR
            domain = "cyber"
            metadata["signature"] = p.get("signature")
            metadata["packet_rate"] = p.get("packet_rate")
            metadata["dst_ip"] = p.get("dst_ip")
            metadata["dst_port"] = p.get("dst_port")
        elif event.threat_type == ThreatType.ANOMALOUS_BEHAVIOR:
            signal_type = SignalType.ANOMALY
            domain = "cyber"
            metadata["anomaly_type"] = p.get("anomaly_type")
            metadata["risk_score"] = p.get("risk_score")
        elif event.threat_type == ThreatType.INSIDER_THREAT:
            signal_type = SignalType.ANOMALY
            domain = "cyber"
            metadata["data_volume"] = p.get("unusual_data_volume_gb") or p.get("data_volume_gb")
            metadata["destination"] = p.get("destination")
        else:
            # Default: treat as generic anomaly
            signal_type = SignalType.ANOMALY
            domain = "cyber" if "network" in event.threat_type.value else "physical"

        if signal_type is None:
            return None

        return Signal(
            timestamp=event.timestamp,
            signal_type=signal_type,
            domain=domain,
            entity_id=entity_id,
            metadata=metadata,
        )

    def _access_request_to_signal(self, request: AccessRequest) -> Optional[Signal]:
        """Convert AccessRequest to a Signal."""
        if not request.user_id:
            return None
        metadata = {
            "resource": request.resource,
            "location": request.location,
            "network": request.network,
            "behavior_context": request.behavior_context,
            "risk_score": request.risk_score,
            "session_id": request.session_id,
        }
        return Signal(
            timestamp=request.timestamp,
            signal_type=SignalType.ACCESS_REQUEST,
            domain="cyber",
            entity_id=request.user_id,
            metadata=metadata,
        )

    # ============================================================
    # History Management
    # ============================================================

    def _get_history(self, entity_id: str) -> EntityHistory:
        """Get or create an EntityHistory for the given ID."""
        if entity_id not in self._histories:
            self._histories[entity_id] = EntityHistory(entity_id)
        return self._histories[entity_id]

    # ============================================================
    # Periodic Evaluation Loop
    # ============================================================

    async def _evaluation_loop(self) -> None:
        """Run evaluations periodically."""
        while self._running:
            await asyncio.sleep(EVALUATION_INTERVAL_SECONDS)
            try:
                for entity_id, history in list(self._histories.items()):
                    await self._evaluate_entity(entity_id, history)
            except Exception as e:
                log.error(f"Error in evaluation loop: {e}")

    async def _evaluate_entity(self, entity_id: str, history: EntityHistory) -> None:
        """
        Evaluate all rules for this entity. If any rule score exceeds threshold,
        publish an alert.
        """
        # Skip if no signals
        if not history.signals:
            return

        results: List[Tuple[int, str, List[ResponseAction]]] = []
        now = datetime.now(timezone.utc)

        # 1. Ghost Login
        ghost_score, ghost_story, ghost_actions = self._evaluate_ghost_login(history)
        if ghost_score >= SCORE_THRESHOLD_GHOST_LOGIN:
            key = f"{entity_id}:ghost_login"
            last = self._last_alert_time.get(key)
            if last is None or (now - last).total_seconds() >= self._alert_cooldown_seconds:
                results.append((ghost_score, ghost_story, ghost_actions))
                self._last_alert_time[key] = now

        # 2. Invisible Insider
        insider_score, insider_story, insider_actions = self._evaluate_insider(history)
        if insider_score >= SCORE_THRESHOLD_INSIDER:
            key = f"{entity_id}:insider"
            last = self._last_alert_time.get(key)
            if last is None or (now - last).total_seconds() >= self._alert_cooldown_seconds:
                results.append((insider_score, insider_story, insider_actions))
                self._last_alert_time[key] = now

        # 3. Tailgating
        tailgate_score, tailgate_story, tailgate_actions = self._evaluate_tailgating(history)
        if tailgate_score >= SCORE_THRESHOLD_TAILGATING:
            key = f"{entity_id}:tailgating"
            last = self._last_alert_time.get(key)
            if last is None or (now - last).total_seconds() >= self._alert_cooldown_seconds:
                results.append((tailgate_score, tailgate_story, tailgate_actions))
                self._last_alert_time[key] = now

        # 4. Ransomware Prelude
        ransom_score, ransom_story, ransom_actions = self._evaluate_ransomware(history)
        if ransom_score >= SCORE_THRESHOLD_RANSOMWARE:
            key = f"{entity_id}:ransomware"
            last = self._last_alert_time.get(key)
            if last is None or (now - last).total_seconds() >= self._alert_cooldown_seconds:
                results.append((ransom_score, ransom_story, ransom_actions))
                self._last_alert_time[key] = now

        # If any result, take the highest score and publish
        if results:
            # Sort by score descending
            results.sort(key=lambda x: x[0], reverse=True)
            top_score, top_story, top_actions = results[0]
            # Also merge actions from all rules that fired
            all_actions = set()
            for _, _, acts in results:
                all_actions.update(acts)
            top_actions = list(dict.fromkeys(all_actions))

            # Determine severity from score
            severity = self._score_to_severity(top_score)

            # Create AgentFinding
            finding = AgentFinding(
                agent_name="ConvergedSecurityEngine",
                event_id=f"csde_{entity_id}_{int(datetime.now().timestamp())}",
                threat_type=ThreatType.CORRELATED_ATTACK,
                severity=severity,
                confidence=min(1.0, top_score / 1000),
                summary=f"Converged risk alert for {entity_id}: {top_story} (score={top_score})",
                actions=top_actions,
                metadata={
                    "entity_id": entity_id,
                    "converged_score": top_score,
                    "triggering_rule": self._get_rule_name(top_score, results),
                    "all_scores": [r[0] for r in results],
                    "contributing_signals": [s.to_dict() for s in list(history.signals)[-20:]],
                }
            )
            await self.bus.publish(finding)
            log.warning(f"Converged alert for {entity_id}: score={top_score}, story={top_story}")

    def _get_rule_name(self, score: int, results: List[Tuple[int, str, List[ResponseAction]]]) -> str:
        """Map score to rule name."""
        for s, _, _ in results:
            if s == score:
                # Try to identify which rule
                if s >= SCORE_THRESHOLD_GHOST_LOGIN:
                    return "ghost_login"
                elif s >= SCORE_THRESHOLD_INSIDER:
                    return "insider"
                elif s >= SCORE_THRESHOLD_TAILGATING:
                    return "tailgating"
                elif s >= SCORE_THRESHOLD_RANSOMWARE:
                    return "ransomware"
        return "unknown"

    def _score_to_severity(self, score: int) -> Severity:
        if score >= 900:
            return Severity.CRITICAL
        elif score >= 750:
            return Severity.HIGH
        elif score >= 500:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    # ============================================================
    # Rule Evaluators
    # ============================================================

    def _evaluate_ghost_login(self, history: EntityHistory) -> Tuple[int, str, List[ResponseAction]]:
        """
        Rule: Login event from a location that contradicts last physical presence.
        Returns (score, story, actions).
        """
        # Find the most recent login signal
        login_signals = history.get_signals_by_type(SignalType.LOGIN, since=datetime.now(timezone.utc) - timedelta(hours=GHOST_LOGIN_WINDOW_HOURS))
        if not login_signals:
            return 0, "", []

        # Also need physical presence signals (PHYSICAL_ACCESS or CCTV) around that time
        physical_signals = history.get_signals_by_type(SignalType.PHYSICAL_ACCESS, since=datetime.now(timezone.utc) - timedelta(hours=GHOST_LOGIN_WINDOW_HOURS))
        cctv_signals = history.get_signals_by_type(SignalType.CCTV, since=datetime.now(timezone.utc) - timedelta(hours=GHOST_LOGIN_WINDOW_HOURS))

        # Combine physical presence signals
        presence_signals = physical_signals + cctv_signals

        # Check if there's a recent physical presence contradicting the login
        # Simplified: if the last physical presence is before the login and location differs, flag.
        latest_login = login_signals[-1]  # most recent
        if not presence_signals:
            # No physical presence at all – suspicious
            return 700, "Login without any recent physical presence.", [ResponseAction.REVOKE_IDENTITY, ResponseAction.NOTIFY_SECURITY]

        latest_presence = presence_signals[-1]
        # Compare timestamps: if login is after presence, but location differs significantly
        if latest_login.timestamp > latest_presence.timestamp:
            login_loc = latest_login.metadata.get("location") or latest_login.metadata.get("ip")
            presence_loc = latest_presence.metadata.get("zone") or latest_presence.metadata.get("location")
            if login_loc and presence_loc and login_loc != presence_loc:
                # Also check geo‑velocity if IP geolocation is available (we could call a service)
                # For now, assume mismatch is suspicious
                score = 850
                story = f"Ghost login: Login from '{login_loc}' while last physical presence at '{presence_loc}'."
                actions = [ResponseAction.REVOKE_IDENTITY, ResponseAction.PSEUDO_LOCK, ResponseAction.ESCALATE_SOC]
                return score, story, actions
        return 0, "", []

    def _evaluate_insider(self, history: EntityHistory) -> Tuple[int, str, List[ResponseAction]]:
        """
        Invisible Insider: accumulation of low‑level anomalies over 72 hours + HR signal.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=INSIDER_WINDOW_HOURS)
        signals = history.get_signals_since(cutoff)
        if len(signals) < 3:
            return 0, "", []

        # Track signals
        data_volume_spike = False
        unusual_access = False
        physical_after_hours = False
        email_exfil = False
        hr_resignation = False

        for sig in signals:
            meta = sig.metadata
            # Data volume spike (INSIDER_THREAT or ANOMALY)
            data_vol = meta.get("data_volume")
            if data_vol is None:
                data_vol = 0
            if sig.signal_type == SignalType.ANOMALY and data_vol > 5.0:
                data_volume_spike = True
            # Unusual access: resource not typical (could be from ANOMALY or ACCESS_REQUEST)
            if sig.signal_type == SignalType.ACCESS_REQUEST:
                resource = meta.get("resource")
                if resource and "sensitive" in resource.lower():
                    unusual_access = True
            # Physical after‑hours (PHYSICAL_ACCESS outside 7‑21)
            if sig.signal_type == SignalType.PHYSICAL_ACCESS:
                hour = sig.timestamp.hour
                if hour < 7 or hour > 21:
                    physical_after_hours = True
            # Email exfil (could be from INSIDER_THREAT with destination)
            if sig.signal_type == SignalType.ANOMALY and meta.get("destination") == "personal_email":
                email_exfil = True
            # HR event (from AgentFinding with hr_signal)
            if sig.signal_type == SignalType.ANOMALY and meta.get("hr_signal") == "resignation":
                hr_resignation = True

        # Count how many signals are present
        indicators = [data_volume_spike, unusual_access, physical_after_hours, email_exfil, hr_resignation]
        count = sum(indicators)
        if count >= 3:
            score = 750 + count * 30  # base 750, +30 per indicator
            score = min(950, score)
            actions = [ResponseAction.REVOKE_IDENTITY, ResponseAction.NOTIFY_SECURITY]
            if hr_resignation:
                actions.append(ResponseAction.ESCALATE_SOC)
            story = f"Invisible Insider: {count} indicators over {INSIDER_WINDOW_HOURS}h (data spike={data_volume_spike}, unusual access={unusual_access}, after‑hours={physical_after_hours}, exfil={email_exfil}, HR={hr_resignation})."
            return score, story, actions
        return 0, "", []

    def _evaluate_tailgating(self, history: EntityHistory) -> Tuple[int, str, List[ResponseAction]]:
        """
        Tailgating: Physical access event with badge mismatch and CCTV detection of two people.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=TAILGATING_WINDOW_MINUTES)
        physical_signals = history.get_signals_by_type(SignalType.PHYSICAL_ACCESS, since=cutoff)
        cctv_signals = history.get_signals_by_type(SignalType.CCTV, since=cutoff)

        if not physical_signals or not cctv_signals:
            return 0, "", []

        # Look for badge mismatch: physical signal with badge_scan=False or face_match=False
        badge_mismatch = any(s.metadata.get("badge_scan") is False or s.metadata.get("face_match") is False for s in physical_signals)
        # CCTV tailgate detection: look for "two_people" or "tailgating" in metadata
        cctv_tailgate = any(s.metadata.get("tailgate_detected") or s.metadata.get("object_alert") == "two_people" for s in cctv_signals)

        if badge_mismatch and cctv_tailgate:
            score = 850
            story = "Tailgating detected: badge mismatch and CCTV confirms two people entering."
            actions = [ResponseAction.LOCK_ZONE, ResponseAction.NOTIFY_SECURITY, ResponseAction.ESCALATE_SOC]
            return score, story, actions
        return 0, "", []

    def _evaluate_ransomware(self, history: EntityHistory) -> Tuple[int, str, List[ResponseAction]]:
        """
        Ransomware Prelude: sequence of DNS anomalies, lateral movement, reconnaissance, off‑hours VPN.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=RANSOMWARE_WINDOW_HOURS)
        signals = history.get_signals_since(cutoff)

        dns_anomaly = False
        lateral_movement = False
        reconnaissance = False
        off_hours_vpn = False

        for sig in signals:
            meta = sig.metadata
            if sig.signal_type == SignalType.NETWORK_BEHAVIOR:
                # DNS anomaly: check for suspicious domain or signature
                if meta.get("signature") == "DNS_TUNNELING" or "dns" in meta.get("signature", "").lower():
                    dns_anomaly = True
                # Lateral movement: many internal destinations
                if meta.get("dst_ip") and meta.get("dst_ip").startswith("10.") or meta.get("dst_ip").startswith("192.168."):
                    lateral_movement = True
            if sig.signal_type == SignalType.ANOMALY:
                if meta.get("anomaly_type") == "reconnaissance":
                    reconnaissance = True
                if meta.get("vpn_usage") and meta.get("hour", 0) < 7 or meta.get("hour", 0) > 21:
                    off_hours_vpn = True
            # Also check off‑hours VPN from ACCESS_REQUEST with network=="vpn" and hour outside 7‑21
            if sig.signal_type == SignalType.ACCESS_REQUEST:
                if meta.get("network") == "vpn":
                    hour = sig.timestamp.hour
                    if hour < 7 or hour > 21:
                        off_hours_vpn = True

        # Count
        indicators = [dns_anomaly, lateral_movement, reconnaissance, off_hours_vpn]
        count = sum(indicators)
        if count >= 3:
            score = 800 + count * 20
            score = min(950, score)
            story = f"Ransomware prelude: {count} indicators over {RANSOMWARE_WINDOW_HOURS}h (DNS={dns_anomaly}, lateral={lateral_movement}, recon={reconnaissance}, off‑hours VPN={off_hours_vpn})."
            actions = [ResponseAction.ISOLATE_ASSET, ResponseAction.PSEUDO_LOCK, ResponseAction.ESCALATE_SOC]
            return score, story, actions
        return 0, "", []

    # ============================================================
    # Public Query Methods (optional)
    # ============================================================

    def get_history(self, entity_id: str) -> Optional[EntityHistory]:
        return self._histories.get(entity_id)

    def get_active_entities(self) -> List[str]:
        return list(self._histories.keys())