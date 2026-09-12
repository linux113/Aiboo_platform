"""
gates/gate1_perimeter.py — Gate 1: Perimeter Intelligence (Zero Trust Edition)

The first and fastest gate. Now also performs Zero Trust checks:
  - Device fingerprint verification
  - Geo‑velocity detection
  - Behavioural risk scoring (if available)
  - Dynamic MFA and access decisions based on risk level

Verdicts:
  PASS     → threat score too low, event allowed through (still logged)
  HOLD     → suspicious, insufficient confidence — forward to Gate 2
  BLOCK    → known signature or clear violation — respond immediately
  ESCALATE → critical severity + high confidence — skip Gate 2, go to Gate 3
"""

from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio
import logging
from typing import Optional, Dict, Any

from core.event_bus import EventBus
from core.events import (
    GateDecision, GateLevel, GateVerdict,
    ResponseAction, Severity, ThreatEvent, ThreatType,
    RiskLevel,
)
from utils.device_fingerprint import get_device_fingerprinter
from utils.geo_velocity import GeoVelocityDetector, GeoLocation

log = logging.getLogger("Gate1.Perimeter")

# Known malicious signatures — immediate BLOCK
_BLOCK_SIGNATURES = {
    "RANSOMWARE_C2", "RCE_EXPLOIT", "SQL_INJECTION",
    "DATA_EXFIL", "ZERO_DAY_EXPLOIT",
}

# Suspicious but not conclusive — HOLD for Gate 2
_HOLD_SIGNATURES = {
    "SSH_BRUTE_FORCE", "PORT_SCAN", "DNS_TUNNELING",
    "UNUSUAL_OUTBOUND", "CREDENTIAL_SPRAY",
}

# Packet rate → severity uplift
_RATE_MAP: list[tuple[int, Severity]] = [
    (15_000, Severity.CRITICAL),
    (8_000,  Severity.HIGH),
    (3_000,  Severity.MEDIUM),
]

# Physical zones only accessible during business hours (06:00–22:00)
_RESTRICTED_ZONES = {"server_room", "server_room_anteroom", "data_vault"}


class Gate1Perimeter:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        # Noise filtering attributes
        self._recent_events: dict[str, list[datetime]] = defaultdict(list)
        self._duplicate_window_seconds = 5
        self._burst_window_seconds = 10
        self._max_events_per_burst = 3

        # ---- Zero Trust utilities ----
        self._fingerprinter = get_device_fingerprinter()
        self._geo_detector = GeoVelocityDetector()
        # Cache previous locations per user for geo‑velocity checks
        self._prev_locations: Dict[str, Dict[str, Any]] = {}
        # Cache trusted device fingerprints per user
        self._trusted_device_hashes: Dict[str, str] = {}

    def start(self) -> None:
        self.bus.subscribe(ThreatEvent, self._evaluate)
        log.info("Gate 1 — Perimeter Intelligence (Zero Trust) — ACTIVE")

    async def _evaluate(self, event: ThreatEvent) -> None:
        # 1. Deduplicate
        if self._is_duplicate(event):
            log.debug("Filtered duplicate event: %s", event.event_id)
            return

        # 2. Burst detection - don't flood pipeline
        if self._is_burst(event):
            log.debug("Filtered burst event: %s", event.event_id)
            return

        # 3. Track for future dedup
        self._track_event(event)

        # 4. Calculate data completeness (real-world data is often partial)
        completeness = self._calculate_completeness(event)

        await asyncio.sleep(0.01)   # fast — sub-10ms perimeter check

        verdict, confidence, reason, actions, severity = self._score_with_noise(event, completeness)

        decision = GateDecision(
            gate        = GateLevel.GATE_1,
            event_id    = event.event_id,
            threat_type = event.threat_type,
            severity    = severity,
            verdict     = verdict,
            confidence  = round(confidence, 2),
            reason      = reason,
            actions     = actions,
            metadata    = {
                "source": event.source,
                "payload": event.payload,
                "data_completeness": completeness,
                "zerotrust_checks": {
                    "geo_risk": self._prev_locations.get(event.payload.get("user_id", ""), {}).get("risk", 0.0),
                    "device_trusted": self._check_device_trust(event),
                }
            },
        )

        log.info(
            "Gate 1 [%s] → %s (conf=%.2f) — %s",
            event.event_id, verdict.value, confidence, reason,
        )
        await self.bus.publish(decision)

    def _score_with_noise(
        self, event: ThreatEvent, completeness: float
    ) -> tuple[GateVerdict, float, str, list[ResponseAction], Severity]:
        p        = event.payload
        severity = event.severity
        actions  = [ResponseAction.LOG]

        # Calculate confidence penalty for incomplete data
        confidence_penalty = (1 - completeness) * 0.3

        # ── Network intrusion ─────────────────────────────────────
        if event.threat_type == ThreatType.NETWORK_INTRUSION:
            sig  = p.get("signature", "")
            rate = p.get("packet_rate", 0)
            anomaly_score = p.get("anomaly_score", 0)

            for threshold, sev in _RATE_MAP:
                if rate >= threshold:
                    severity = sev
                    break

            # Critical signatures - even with low completeness
            if sig in _BLOCK_SIGNATURES:
                confidence = 0.95 - confidence_penalty
                actions += [ResponseAction.ISOLATE_ASSET, ResponseAction.PSEUDO_LOCK,
                            ResponseAction.ALERT_DASHBOARD]
                verdict = GateVerdict.ESCALATE if severity == Severity.CRITICAL \
                          else GateVerdict.BLOCK
                return verdict, confidence, f"Known malicious signature: {sig}", actions, severity

            # High anomaly score from statistical baseline
            if anomaly_score > 2.5:
                confidence = 0.85 - confidence_penalty
                actions += [ResponseAction.ISOLATE_ASSET, ResponseAction.ALERT_DASHBOARD]
                return GateVerdict.BLOCK, confidence, f"Statistical anomaly (z={anomaly_score:.1f})", actions, Severity.HIGH

            if sig in _HOLD_SIGNATURES:
                actions.append(ResponseAction.ALERT_DASHBOARD)
                return GateVerdict.HOLD, 0.60, \
                       f"Suspicious signature {sig} — forwarding to Gate 2", actions, severity

            if severity in (Severity.HIGH, Severity.CRITICAL):
                actions.append(ResponseAction.ALERT_DASHBOARD)
                return GateVerdict.HOLD, 0.50, \
                       f"High packet rate ({rate}/s) — forwarding to Gate 2", actions, severity

            return GateVerdict.PASS, 0.20, "Traffic within normal bounds", actions, severity

        # ── Identity mismatch (with Zero Trust enhancements) ─────
        if event.threat_type == ThreatType.IDENTITY_MISMATCH:
            bio   = float(p.get("biometric_score", 1.0))
            loc   = p.get("detected_location", "")
            anomaly_score = p.get("anomaly_score", 0)
            user_id = p.get("user_id", "unknown")

            # ---- Zero Trust: Device fingerprint check ----
            device_trusted = self._check_device_trust(event)
            device_risk = 0.0 if device_trusted else 0.4

            # ---- Zero Trust: Geo‑velocity check ----
            geo_risk, geo_reason = self._check_geo_velocity(user_id, loc, event.timestamp)

            # ---- Combine scores ----
            confidence = 0.40  # base
            if bio < 0.30:
                confidence += 0.30
            elif bio < 0.60:
                confidence += 0.15

            if loc and "unknown" in loc.lower():
                confidence += 0.20

            if anomaly_score > 2:
                confidence += 0.15

            # Add Zero Trust penalties
            confidence += geo_risk * 0.4
            confidence += device_risk * 0.3

            # Apply confidence penalty for incomplete data
            confidence -= confidence_penalty
            confidence = max(0.0, min(confidence, 1.0))

            # ---- Determine actions and verdict ----
            if confidence >= 0.85:
                verdict = GateVerdict.ESCALATE
                severity = Severity.CRITICAL
                actions += [ResponseAction.BLOCK_ACCESS, ResponseAction.FORCE_LOGOUT,
                            ResponseAction.ESCALATE_SOC, ResponseAction.NOTIFY_SECURITY]
                if not device_trusted:
                    actions.append(ResponseAction.QUARANTINE_DEVICE)
                reason = f"Critical identity failure: bio={bio:.2f}, loc={loc!r}, geo_risk={geo_risk:.2f}, device={'untrusted' if not device_trusted else 'trusted'}"
            elif confidence >= 0.65:
                verdict = GateVerdict.BLOCK
                severity = Severity.HIGH
                actions += [ResponseAction.REVOKE_IDENTITY, ResponseAction.STEP_UP_AUTH,
                            ResponseAction.CHALLENGE_MFA, ResponseAction.NOTIFY_SECURITY]
                reason = f"High identity risk: bio={bio:.2f}, geo_risk={geo_risk:.2f}"
            elif confidence >= 0.40:
                verdict = GateVerdict.HOLD
                severity = Severity.MEDIUM
                actions += [ResponseAction.ALERT_DASHBOARD, ResponseAction.STEP_UP_AUTH]
                reason = f"Suspicious identity: bio={bio:.2f}, geo_risk={geo_risk:.2f} — forwarding to Gate 2"
            else:
                verdict = GateVerdict.PASS
                reason = "Identity pre-screen passed"

            actions = list(dict.fromkeys(actions))  # deduplicate
            return verdict, confidence, reason, actions, severity

        # ── Physical intrusion ────────────────────────────────────
        if event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            zone  = p.get("zone", "")
            badge = bool(p.get("badge_scan", True))
            face  = bool(p.get("face_match", True))

            if not badge and not face and zone in _RESTRICTED_ZONES:
                actions += [ResponseAction.LOCK_ZONE, ResponseAction.ALERT_DASHBOARD,
                            ResponseAction.NOTIFY_SECURITY]
                return GateVerdict.ESCALATE, 0.92, \
                       f"No auth in critical zone {zone!r}", actions, Severity.CRITICAL

            if not badge or not face:
                actions.append(ResponseAction.ALERT_DASHBOARD)
                return GateVerdict.HOLD, 0.55, \
                       "Partial auth failure — forwarding to Gate 2", actions, severity

            return GateVerdict.PASS, 0.20, "Physical perimeter check passed", actions, severity

        # ── Insider / anomalous ───────────────────────────────────
        actions.append(ResponseAction.ALERT_DASHBOARD)
        return GateVerdict.HOLD, 0.45, \
               "Insider/anomalous event — Gate 2 behavioural analysis required", \
               actions, severity

    # ── Zero Trust helper methods ─────────────────────────────────────────

    def _check_device_trust(self, event: ThreatEvent) -> bool:
        """
        Verify device fingerprint against stored trusted fingerprint.
        Returns True if device is trusted, False otherwise.
        """
        p = event.payload
        user_id = p.get("user_id")
        device_info = p.get("device_info", {})
        if not user_id or not device_info:
            return True  # no info, assume trusted (or could return False for strict)

        device_id = device_info.get("device_id")
        if not device_id:
            return True

        # Generate current fingerprint
        current_fp = self._fingerprinter.get_fingerprint(device_id)

        # Check if we have a stored fingerprint for this user
        stored_hash = self._trusted_device_hashes.get(user_id)
        if not stored_hash:
            # First time: trust this device (or could require approval)
            self._trusted_device_hashes[user_id] = current_fp.fingerprint_hash
            return True

        # Compare stored hash with current
        return stored_hash == current_fp.fingerprint_hash

    def _check_geo_velocity(self, user_id: str, location_str: str, timestamp: datetime) -> tuple[float, str]:
        """
        Check if travel from previous location to current is plausible.
        Returns (risk_score, reason).
        """
        if not user_id or not location_str:
            return 0.0, "No location data"

        # Simple mock geocoding: use deterministic hash to generate coordinates
        def hash_to_coords(s: str):
            import hashlib
            h = hashlib.md5(s.encode()).hexdigest()
            lat = (int(h[:8], 16) % 180) - 90
            lon = (int(h[8:16], 16) % 360) - 180
            return lat, lon

        prev = self._prev_locations.get(user_id)
        if not prev:
            cur_lat, cur_lon = hash_to_coords(location_str)
            self._prev_locations[user_id] = {
                "location": location_str,
                "timestamp": timestamp,
                "lat": cur_lat,
                "lon": cur_lon,
                "risk": 0.0,
            }
            return 0.0, "First location recorded"

        # If same location, no risk
        if location_str == prev["location"]:
            return 0.0, "Same location"

        cur_lat, cur_lon = hash_to_coords(location_str)
        prev_lat = prev.get("lat", 0.0)
        prev_lon = prev.get("lon", 0.0)

        loc1 = GeoLocation(
            latitude=prev_lat,
            longitude=prev_lon,
            timestamp=prev["timestamp"],
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
            "risk": risk,
        }

        if is_impossible:
            return risk, reason
        else:
            return risk * 0.5, reason  # scale down for lower risk

    # ── Noise filtering helper methods (unchanged) ────────────────

    def _is_duplicate(self, event: ThreatEvent) -> bool:
        """Check if identical event occurred recently"""
        fingerprint = self._fingerprint(event)
        now = datetime.now()
        cutoff = now - timedelta(seconds=self._duplicate_window_seconds)
        self._recent_events[fingerprint] = [t for t in self._recent_events[fingerprint] if t > cutoff]
        return len(self._recent_events[fingerprint]) > 0

    def _fingerprint(self, event: ThreatEvent) -> str:
        """Create event fingerprint for deduplication"""
        p = event.payload
        key_fields = [
            event.threat_type.value,
            p.get("src_ip", ""),
            p.get("user_id", ""),
            p.get("dst_port", ""),
            p.get("zone", ""),
        ]
        return ":".join(str(f) for f in key_fields if f)

    def _is_burst(self, event: ThreatEvent) -> bool:
        """Detect and filter event bursts"""
        fingerprint = self._fingerprint(event) + ":burst"
        now = datetime.now()
        cutoff = now - timedelta(seconds=self._burst_window_seconds)
        self._recent_events[fingerprint] = [t for t in self._recent_events[fingerprint] if t > cutoff]
        return len(self._recent_events[fingerprint]) >= self._max_events_per_burst

    def _track_event(self, event: ThreatEvent):
        """Track event for future dedup/burst detection"""
        fingerprint = self._fingerprint(event)
        self._recent_events[fingerprint].append(datetime.now())
        burst_fingerprint = fingerprint + ":burst"
        self._recent_events[burst_fingerprint].append(datetime.now())

    def _calculate_completeness(self, event: ThreatEvent) -> float:
        """Calculate how complete/trustworthy the event data is"""
        p = event.payload

        expected_fields = {
            ThreatType.NETWORK_INTRUSION: ["src_ip", "dst_port", "signature"],
            ThreatType.IDENTITY_MISMATCH: ["user_id", "biometric_score"],
            ThreatType.PHYSICAL_INTRUSION: ["zone", "badge_scan"],
            ThreatType.INSIDER_THREAT: ["user_id", "unusual_data_volume_gb"],
        }.get(event.threat_type, [])

        if not expected_fields:
            return 0.5

        present = sum(1 for f in expected_fields if p.get(f))
        completeness = present / len(expected_fields)

        # Windows events often have raw string data
        if p.get("strings") and completeness < 0.5:
            completeness = max(completeness, 0.3)

        return completeness