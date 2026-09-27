"""
agents/identity_agent.py — Identity Verification Agent

Cross-checks claimed identity against biometric scores,
location data, access credentials, and behavioural patterns.
Detects mismatches, impossible travel, and device anomalies.

Enhanced for Layer 3 Cyber‑Physical Convergence – emits rich location,
device, and geo‑velocity metadata for the Converged Security Engine.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from cachetools import TTLCache

from core.base_agent import BaseAgent
from core.config import config
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType, RiskLevel,
)
from utils.device_fingerprint import get_device_fingerprinter, DeviceFingerprint
from utils.geo_velocity import GeoVelocityDetector, GeoLocation

# Biometric confidence thresholds
_BIOMETRIC_TRUSTED   = 0.75
_BIOMETRIC_UNCERTAIN = 0.50


class IdentityVerificationAgent(BaseAgent):
    def __init__(self, bus: EventBus) -> None:
        super().__init__("IdentityAgent", bus)
        # ---- Zero Trust utilities ----
        self._fingerprinter = get_device_fingerprinter()
        self._geo_detector = GeoVelocityDetector()
        # Cache previous locations per user for geo‑velocity checks (TTLCache bounded)
        self._prev_locations: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=3600)
        # Cache device fingerprints per user (user_id -> fingerprint_hash) (TTLCache bounded)
        self._user_device_hashes: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)

    def can_handle(self, event: ThreatEvent) -> bool:
        return event.threat_type in (
            ThreatType.IDENTITY_MISMATCH,
            ThreatType.INSIDER_THREAT,
            # Optionally also handle access requests if ZeroTrustAgent not used
            # ThreatType.ACCESS_REQUEST,
        )

    async def analyse(self, event: ThreatEvent) -> AgentFinding:
        # Simulate biometric / IdP lookup latency
        await asyncio.sleep(0.06)

        p = event.payload
        actions: list[ResponseAction] = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        confidence = 0.50
        severity = event.severity

        user_id = p.get("user_id", "unknown")
        bio_score = float(p.get("biometric_score", 1.0))
        claimed = p.get("claimed_location", "")
        detected = p.get("detected_location", "")
        # ---- NEW: Latitude/longitude for precise geo correlation ----
        latitude = p.get("latitude")
        longitude = p.get("longitude")
        device_id = p.get("device_id") or p.get("device_info", {}).get("device_id")

        # ---- Standard checks ----
        location_mismatch = bool(claimed and detected and claimed != detected)
        biometric_fail = bio_score < _BIOMETRIC_UNCERTAIN

        # ---- Zero Trust: Geo‑velocity check ----
        geo_risk = 0.0
        geo_reason = ""
        if detected or claimed:
            geo_risk, geo_reason = await self._check_geo_velocity(user_id, detected or claimed, event.timestamp)

        # ---- Zero Trust: Device fingerprint verification ----
        device_risk = 0.0
        device_fingerprint_match = True
        device_info = p.get("device_info", {})
        if device_info:
            device_risk, device_fingerprint_match = await self._verify_device(user_id, device_info)

        # ---- Calculate combined identity risk ----
        # Base risk from biometric and location mismatch
        base_risk = 0.0
        if biometric_fail:
            base_risk += 0.3
            actions.append(ResponseAction.REVOKE_IDENTITY)
        if location_mismatch:
            base_risk += 0.2
            actions.append(ResponseAction.REVOKE_IDENTITY)

        # Add geo‑velocity risk (0–0.4)
        base_risk += geo_risk * 0.4

        # Add device risk (0–0.3)
        base_risk += device_risk * 0.3

        # Combine with existing confidence (start from 0.5)
        confidence = 0.5 + base_risk

        # ---- Determine risk level and actions ----
        risk_level = self._risk_score_to_level(confidence)

        # Apply additional actions based on risk
        if risk_level == RiskLevel.LOW:
            # No extra actions
            pass
        elif risk_level == RiskLevel.MEDIUM:
            actions.append(ResponseAction.STEP_UP_AUTH)
            actions.append(ResponseAction.CHALLENGE_MFA)
        elif risk_level == RiskLevel.HIGH:
            actions.append(ResponseAction.STEP_UP_AUTH)
            actions.append(ResponseAction.CHALLENGE_MFA)
            actions.append(ResponseAction.NOTIFY_SECURITY)
            # Might also revoke identity if already not done
            if ResponseAction.REVOKE_IDENTITY not in actions:
                actions.append(ResponseAction.REVOKE_IDENTITY)
        else:  # CRITICAL
            actions.append(ResponseAction.BLOCK_ACCESS)
            actions.append(ResponseAction.FORCE_LOGOUT)
            actions.append(ResponseAction.NOTIFY_SECURITY)
            actions.append(ResponseAction.ESCALATE_SOC)
            if ResponseAction.REVOKE_IDENTITY not in actions:
                actions.append(ResponseAction.REVOKE_IDENTITY)

        # ---- Impossible travel override ----
        if geo_risk > 0.7:
            severity = Severity.CRITICAL
            actions.append(ResponseAction.PSEUDO_LOCK)
            actions.append(ResponseAction.ESCALATE_SOC)

        # ---- Device mismatch override ----
        if not device_fingerprint_match and device_risk > 0.5:
            actions.append(ResponseAction.QUARANTINE_DEVICE)
            severity = Severity.HIGH

        # Ensure severity is at least MEDIUM if any risk > 0.4
        if confidence > 0.6 and severity == Severity.LOW:
            severity = Severity.MEDIUM
        if confidence > 0.8:
            severity = Severity.HIGH
        if confidence > 0.9:
            severity = Severity.CRITICAL

        # Clean and deduplicate actions
        actions = list(dict.fromkeys(actions))

        # ---- Build summary ----
        summary_parts = [
            f"Identity verification for {user_id}:",
            f"biometric={'FAIL' if biometric_fail else 'PASS'} ({bio_score:.2f})",
            f"location={'MISMATCH' if location_mismatch else 'OK'} ({claimed!r} vs {detected!r})",
        ]
        if geo_risk > 0.1:
            summary_parts.append(f"geo‑velocity risk={geo_risk:.2f} ({geo_reason})")
        if device_info:
            summary_parts.append(f"device={'trusted' if device_fingerprint_match else 'UNTRUSTED'} (risk={device_risk:.2f})")
        summary_parts.append(f"overall risk={confidence:.2f} ({risk_level.value})")

        summary = " — ".join(summary_parts)

        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=round(min(confidence, 1.0), 2),
            summary=summary,
            actions=actions,
            metadata={
                # ---- Core identity fields ----
                "user_id": user_id,
                "entity_id": user_id,               # Alias for CSDE
                "biometric_score": bio_score,
                "location_mismatch": location_mismatch,
                "claimed_location": claimed,
                "detected_location": detected,
                "latitude": latitude,
                "longitude": longitude,
                # ---- Geo‑velocity ----
                "geo_risk": geo_risk,
                "geo_reason": geo_reason,
                # ---- Device ----
                "device_id": device_id,
                "device_trusted": device_fingerprint_match,
                "device_risk": device_risk,
                # ---- Overall ----
                "risk_level": risk_level.value,
            },
        )

    # ---- Zero Trust helper methods ----

    async def _check_geo_velocity(self, user_id: str, location_str: str, timestamp: datetime) -> tuple[float, str]:
        """
        Check if travel from previous location to current is plausible.
        Returns (risk_score, reason).
        """
        # Try to parse location string into coordinates (simple mock)
        # In production you'd use a geocoding service. For now we simulate.
        # We store previous location as (lat, lon, timestamp)
        prev = self._prev_locations.get(user_id)
        if not prev:
            # Store current as first location
            self._prev_locations[user_id] = {
                "location": location_str,
                "timestamp": timestamp,
                # Mock coordinates (random for demo)
                "lat": 0.0,
                "lon": 0.0,
            }
            return 0.0, "First location recorded"

        # Mock coordinates: for demo, if location changed, assign fake coordinates
        # In real implementation, you'd geocode location_str -> lat/lon.
        # For demonstration, we use a simple heuristic: if location string differs, compute a fake distance.
        if location_str == prev["location"]:
            # Same location, no risk
            return 0.0, "Same location"

        # Simulate coordinates: in real code, you'd geocode both.
        # Here we assign arbitrary lat/lon based on string length to simulate movement.
        import hashlib
        def hash_to_coords(s):
            h = hashlib.md5(s.encode()).hexdigest()
            lat = (int(h[:8], 16) % 180) - 90
            lon = (int(h[8:16], 16) % 360) - 180
            return lat, lon

        cur_lat, cur_lon = hash_to_coords(location_str)
        prev_lat = self._prev_locations[user_id].get("lat", 0.0)
        prev_lon = self._prev_locations[user_id].get("lon", 0.0)

        # Create GeoLocation objects
        loc1 = GeoLocation(
            latitude=prev_lat,
            longitude=prev_lon,
            timestamp=self._prev_locations[user_id]["timestamp"],
            location_name=prev["location"]
        )
        loc2 = GeoLocation(
            latitude=cur_lat,
            longitude=cur_lon,
            timestamp=timestamp,
            location_name=location_str
        )

        is_impossible, risk, reason = self._geo_detector.detect_impossible_travel(loc1, loc2)

        # Store current for next check
        self._prev_locations[user_id] = {
            "location": location_str,
            "timestamp": timestamp,
            "lat": cur_lat,
            "lon": cur_lon,
        }

        if is_impossible:
            return risk, reason
        else:
            return risk * 0.5, reason  # scale down for lower risk

    async def _verify_device(self, user_id: str, device_info: Dict) -> tuple[float, bool]:
        """
        Verify device fingerprint against stored record.
        Returns (risk_score, is_match).
        """
        device_id = device_info.get("device_id")
        if not device_id:
            return 0.0, True  # no device info, assume ok

        # Generate current fingerprint
        current_fp = self._fingerprinter.get_fingerprint(device_id)

        # Check if we have a stored fingerprint for this user
        stored_hash = self._user_device_hashes.get(user_id)
        if not stored_hash:
            # First time for this user: store the fingerprint hash as trusted
            self._user_device_hashes[user_id] = current_fp.fingerprint_hash
            return 0.0, True

        # Compare stored hash with current
        if stored_hash != current_fp.fingerprint_hash:
            # Mismatch – could be a different device or cloned device
            # Calculate mismatch severity based on fingerprint confidence
            risk = 1.0 - current_fp.confidence
            return risk, False
        else:
            # Match – low risk
            return 0.1, True

    @staticmethod
    def _risk_score_to_level(score: float) -> RiskLevel:
        if score >= 0.9:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW