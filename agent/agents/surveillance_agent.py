"""
agents/surveillance_agent.py — Physical Surveillance Analysis Agent
 
Processes camera feed events, motion anomaly scores, badge data,
and facial recognition results to detect physical intrusions,
tailgating, and unauthorised zone access.
 
Enhanced for Layer 3 Cyber‑Physical Convergence – includes user_id,
badge_id, face_match_confidence, tailgate_detected, loitering_detected
in metadata for consumption by the Converged Security Engine.
"""
 
from __future__ import annotations
 
import asyncio
 
from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType,
)
 
# Zones ordered by criticality (higher index = more critical)
_ZONE_CRITICALITY: dict[str, int] = {
    "public_lobby":         0,
    "office_floor":         1,
    "restricted_corridor":  2,
    "server_room_anteroom": 3,
    "server_room":          4,
    "executive_suite":      3,
    "data_vault":           4,
}
 
_MOTION_ANOMALY_HIGH = 0.80
 
 
class SurveillanceAgent(BaseAgent):
    def __init__(self, bus: EventBus) -> None:
        super().__init__("SurveillanceAgent", bus)
 
    def can_handle(self, event: ThreatEvent) -> bool:
        return event.threat_type == ThreatType.PHYSICAL_INTRUSION
 
    async def analyse(self, event: ThreatEvent) -> AgentFinding:
        # Simulate frame analysis / face recognition API call
        await asyncio.sleep(0.08)
 
        p = event.payload
        actions: list[ResponseAction] = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        confidence = 0.45
        severity   = event.severity
 
        # Extract core physical data
        zone          = p.get("zone", "unknown")
        face_match    = bool(p.get("face_match", True))
        badge_scan    = bool(p.get("badge_scan", True))
        motion_score  = float(p.get("motion_anomaly_score", 0.0))
        zone_level    = _ZONE_CRITICALITY.get(zone, 0)
 
        # ---- NEW: Additional fields for cyber‑physical convergence ----
        user_id       = p.get("user_id") or p.get("person_id") or p.get("entity_id")
        badge_id      = p.get("badge_id")
        face_match_conf = float(p.get("face_match_confidence", 0.0))
        tailgate_detected = bool(p.get("tailgate_detected", False))
        loitering_detected = bool(p.get("loitering_detected", False))
        # ---- End new fields ----
 
        # ── Evidence accumulation ────────────────────────────────
        if not face_match:
            confidence += 0.20
            actions.append(ResponseAction.LOCK_ZONE)
 
        if not badge_scan:
            confidence += 0.20
 
        if motion_score >= _MOTION_ANOMALY_HIGH:
            confidence += 0.15
            actions.append(ResponseAction.NOTIFY_SECURITY)
 
        # Critical zones trigger immediate escalation
        if zone_level >= 3:
            severity   = Severity.CRITICAL
            confidence = min(confidence + 0.10, 1.0)
            actions.extend([
                ResponseAction.LOCK_ZONE,
                ResponseAction.NOTIFY_SECURITY,
                ResponseAction.ESCALATE_SOC,
            ])
        elif zone_level >= 2:
            severity = Severity.HIGH
 
        no_auth = not face_match and not badge_scan
        if no_auth:
            actions.append(ResponseAction.ESCALATE_SOC)
 
        summary = (
            f"Unauthorised access attempt in zone '{zone}' "
            f"(criticality level {zone_level}). "
            f"Face match: {'yes' if face_match else 'NO'}, "
            f"badge: {'yes' if badge_scan else 'NO'}, "
            f"motion anomaly: {motion_score:.2f}."
        )
 
        return AgentFinding(
            agent_name  = self.name,
            event_id    = event.event_id,
            threat_type = event.threat_type,
            severity    = severity,
            confidence  = round(min(confidence, 1.0), 2),
            summary     = summary,
            actions     = list(dict.fromkeys(actions)),
            metadata    = {
                "zone":                 zone,
                "zone_level":           zone_level,
                "face_match":           face_match,
                "badge_scan":           badge_scan,
                "motion_score":         motion_score,
                # ---- NEW: convergence fields ----
                "user_id":              user_id,
                "badge_id":             badge_id,
                "face_match_confidence": face_match_conf,
                "tailgate_detected":    tailgate_detected,
                "loitering_detected":   loitering_detected,
                "person_id":            user_id,  # alias for CSDE
                "entity_id":            user_id,
                # ---- end new fields ----
            },
        )