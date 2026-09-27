"""
agents/zero_trust_agent.py — Zero Trust Verification Agent
# SPLIT: This file is 1317 lines. Suggested splits:
#   - agents/zero_trust_agent.py         (core agent class)
#   - agents/zero_trust_models.py        (TrustedDevice, BehavioralProfile dataclasses)
#   - agents/zero_trust_verifiers.py     (verify_identity, verify_device, verify_network, etc.)
#   - agents/zero_trust_risk.py          (risk scoring, anomaly detection)
#   - agents/zero_trust_session.py       (session management, PAM)

Core Layer 1 Zero Trust agent that implements:
- Continuous verification of users, devices, networks, and behavior
- Dynamic risk scoring for every access attempt
- Adaptive MFA based on risk level
- Device health and posture assessment
- Behavioral anomaly detection
- Geo-velocity detection
- Just-In-Time (JIT) privileged access management
- Microsegmentation enforcement
- Software Defined Perimeter (SDP) verification
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from cachetools import TTLCache
import hashlib
import json
import re

from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType, RiskLevel,
    AccessRequest, ZeroTrustDecision
)
from utils.device_fingerprint import DeviceFingerprinter, get_device_fingerprinter
from utils.geo_velocity import GeoVelocityDetector, GeoLocation
from core.config import config

log = logging.getLogger("ZeroTrustAgent")

# ============================================
# Constants and Configuration
# ============================================

# Risk scoring weights
RISK_WEIGHTS = {
    "identity": 0.30,      # Identity verification score
    "device": 0.25,        # Device trust score
    "network": 0.15,       # Network security score
    "location": 0.15,      # Location verification score
    "behavior": 0.15,      # Behavioral anomaly score
}

# Risk thresholds
RISK_THRESHOLDS = {
    "low": 0.3,            # Risk score below 0.3 = LOW risk
    "medium": 0.5,         # Risk score 0.3-0.5 = MEDIUM risk
    "high": 0.7,           # Risk score 0.5-0.7 = HIGH risk
    "critical": 0.9,       # Risk score above 0.9 = CRITICAL risk
}

# MFA requirements by risk level
MFA_REQUIREMENTS = {
    RiskLevel.LOW: [],                                           # No MFA required
    RiskLevel.MEDIUM: ["otp"],                                   # OTP only
    RiskLevel.HIGH: ["otp", "biometric"],                        # OTP + Biometric
    RiskLevel.CRITICAL: ["otp", "biometric", "security_key"],    # Full verification
}

# Privileged access roles
PRIVILEGED_ROLES = {"admin", "root", "superuser", "security_admin", "devops_admin"}

# Business hours (for access control)
BUSINESS_HOURS_START = 7   # 7 AM
BUSINESS_HOURS_END = 21    # 9 PM

# Session timeout (seconds)
SESSION_TIMEOUT = 3600     # 1 hour
SESSION_REFRESH = 300      # 5 minutes (re-verify every 5 minutes)

# Maximum data transfer for privileged users (GB)
MAX_DATA_TRANSFER_GB = 10

# Restricted zones that require special verification
RESTRICTED_ZONES = {
    "server_room", "server_room_anteroom", "data_vault", 
    "network_operations", "security_operations", "crypto_lab"
}


@dataclass
class TrustedDevice:
    """Record of a trusted device in the system"""
    device_id: str
    fingerprint_hash: str
    hardware_id: str
    mac_addresses: List[str]
    user_id: str
    first_seen: datetime
    last_verified: datetime
    trust_score: float
    is_active: bool
    device_type: str
    os_info: Dict[str, Any]
    last_known_ip: str


@dataclass
class BehavioralProfile:
    """Behavioral profile for a user/entity"""
    user_id: str
    typical_hours: List[int]          # Hours when user typically works
    typical_locations: List[str]      # Typical login locations
    typical_devices: List[str]        # Typical device IDs
    typical_data_volume: float        # Average data volume per session (GB)
    typical_apps: List[str]           # Typical applications used
    access_patterns: List[str]        # Typical sequences of access
    anomaly_threshold: float          # Threshold for behavioral anomalies
    last_updated: datetime
    risk_score: float = 0.0
    occurrences: int = 0


class ZeroTrustAgent(BaseAgent):
    """
    Core Zero Trust verification agent implementing Layer 1 security.
    
    This agent continuously verifies every access attempt using:
    1. Identity verification (who you are)
    2. Device verification (what you're using)
    3. Network verification (where you are)
    4. Location verification (where you claim to be)
    5. Behavioral verification (how you normally behave)
    """
    
    def __init__(self, bus: EventBus) -> None:
        super().__init__("ZeroTrustAgent", bus)
        
        # Initialize fingerprinting
        self._fingerprinter = get_device_fingerprinter()
        self._geo_velocity = GeoVelocityDetector()
        
        # Track trusted devices (TTLCache bounded)
        self._trusted_devices: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        
        # Track behavioral profiles (TTLCache bounded)
        self._behavioral_profiles: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        
        # Track active sessions (TTLCache bounded)
        self._active_sessions: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=3600)
        
        # Track recent access attempts (for correlation)
        self._recent_access: Dict[str, List[datetime]] = defaultdict(list)
        
        # Track privilege elevation requests
        self._privilege_requests: Dict[str, List[datetime]] = defaultdict(list)
        
        # Track blocked attempts (for detection patterns)
        self._blocked_attempts: Dict[str, int] = defaultdict(int)
        
        # Zero Trust configuration
        self._config = {
            "session_timeout": SESSION_TIMEOUT,
            "session_refresh": SESSION_REFRESH,
            "max_data_transfer_gb": MAX_DATA_TRANSFER_GB,
            "business_hours_start": BUSINESS_HOURS_START,
            "business_hours_end": BUSINESS_HOURS_END,
            "privileged_roles": PRIVILEGED_ROLES,
            "restricted_zones": RESTRICTED_ZONES,
        }
        
        log.info("ZeroTrustAgent initialized with Layer 1 security controls")
    
    def can_handle(self, event: ThreatEvent) -> bool:
        """Handle access-related events and security events requiring verification"""
        return event.threat_type in (
            ThreatType.ACCESS_REQUEST,
            ThreatType.IDENTITY_MISMATCH,
            ThreatType.NETWORK_INTRUSION,
            ThreatType.PHYSICAL_INTRUSION,
            ThreatType.ANOMALOUS_BEHAVIOR,
            ThreatType.INSIDER_THREAT,
        )
    
    async def analyse(self, event: ThreatEvent) -> Optional[AgentFinding]:
        """
        Perform Zero Trust analysis on the event.
        This is the main entry point for all Zero Trust evaluations.
        """
        # Determine event type and route to appropriate handler
        if event.threat_type == ThreatType.ACCESS_REQUEST:
            return await self._handle_access_request(event)
        elif event.threat_type == ThreatType.IDENTITY_MISMATCH:
            return await self._handle_identity_verification(event)
        elif event.threat_type == ThreatType.NETWORK_INTRUSION:
            return await self._handle_network_verification(event)
        elif event.threat_type == ThreatType.PHYSICAL_INTRUSION:
            return await self._handle_physical_verification(event)
        elif event.threat_type == ThreatType.ANOMALOUS_BEHAVIOR:
            return await self._handle_behavioral_analysis(event)
        else:
            return await self._handle_insider_threat(event)
    
    # ============================================
    # Event Handlers
    # ============================================
    
    async def _handle_access_request(self, event: ThreatEvent) -> AgentFinding:
        """Handle an access request with full Zero Trust verification"""
        p = event.payload
        
        user_id = p.get("user_id", "unknown")
        device_info = p.get("device_info", {})
        network_info = p.get("network_info", {})
        location_info = p.get("location", {})
        resource = p.get("resource", "unknown")
        role = p.get("role", "user")
        auth_token = p.get("auth_token", None)
        
        log.info(f"Processing access request: {user_id} -> {resource}")
        
        # 1. Verify identity (who you are)
        identity_result = await self._verify_identity(user_id, auth_token, p)
        
        # 2. Verify device (what you're using)
        device_result = await self._verify_device(user_id, device_info, p)
        
        # 3. Verify network (where you're connecting from)
        network_result = await self._verify_network(network_info, p)
        
        # 4. Verify location (where you claim to be)
        location_result = await self._verify_location(user_id, location_info, p)
        
        # 5. Check behavioral patterns (how you normally behave)
        behavior_result = await self._check_behavioral_patterns(user_id, event)
        
        # 6. Check for geo-velocity violations
        geo_result = await self._check_geo_velocity(user_id, location_info, event.timestamp)
        
        # 7. Check if this is a privileged access request
        is_privileged = role.lower() in self._config["privileged_roles"]
        if is_privileged:
            privilege_result = await self._check_privileged_access(user_id, role, resource, event)
        else:
            privilege_result = {"is_allowed": True, "risk_score": 0.0, "reason": "Non-privileged access"}
        
        # 8. Calculate combined risk score
        risk_score = self._calculate_combined_risk_score({
            "identity": identity_result.get("risk_score", 0.0),
            "device": device_result.get("risk_score", 0.0),
            "network": network_result.get("risk_score", 0.0),
            "location": location_result.get("risk_score", 0.0),
            "behavior": behavior_result.get("risk_score", 0.0),
            "geo": geo_result.get("risk_score", 0.0),
            "privilege": privilege_result.get("risk_score", 0.0),
        })
        
        # 9. Determine risk level
        risk_level = self._determine_risk_level(risk_score)
        
        # 10. Determine required MFA actions
        required_mfa = MFA_REQUIREMENTS.get(risk_level, [])
        
        # 11. Build response actions
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        
        # Check if this is a known blocked entity
        if user_id in self._blocked_attempts and self._blocked_attempts[user_id] > 5:
            risk_level = RiskLevel.CRITICAL
            risk_score = min(risk_score + 0.3, 1.0)
        
        # Determine if access should be allowed
        access_allowed = False
        if risk_level == RiskLevel.LOW:
            access_allowed = True
            actions.append(ResponseAction.ALLOW_ACCESS)
        elif risk_level == RiskLevel.MEDIUM:
            if required_mfa:
                actions.append(ResponseAction.CHALLENGE_MFA)
                actions.append(ResponseAction.STEP_UP_AUTH)
                access_allowed = True  # Allow after MFA
            else:
                access_allowed = True
        elif risk_level == RiskLevel.HIGH:
            actions.append(ResponseAction.CHALLENGE_MFA)
            actions.append(ResponseAction.STEP_UP_AUTH)
            access_allowed = True  # Allow after strong verification
            actions.append(ResponseAction.NOTIFY_SECURITY)
        else:  # CRITICAL
            actions.append(ResponseAction.BLOCK_ACCESS)
            actions.append(ResponseAction.FORCE_LOGOUT)
            actions.append(ResponseAction.NOTIFY_SECURITY)
            actions.append(ResponseAction.ESCALATE_SOC)
            access_allowed = False
            self._blocked_attempts[user_id] += 1
        
        # If privileged, apply JIT access
        if is_privileged and access_allowed:
            actions.append(ResponseAction.GRANT_TEMP_PRIVILEGE)
            actions.append(ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION)
        
        # Update behavioral profile
        await self._update_behavioral_profile(user_id, event, risk_score)
        
        # Track session
        if access_allowed:
            session_id = await self._create_session(user_id, device_info, risk_level)
            p["session_id"] = session_id
        
        # Build summary
        summary = self._build_verification_summary(
            user_id, resource, access_allowed, risk_level, risk_score,
            identity_result, device_result, location_result, geo_result,
            privilege_result, required_mfa
        )
        
        # Check for correlation with other threats
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            # Check if this is part of a coordinated attack
            correlated = await self._check_correlation(user_id, event, risk_level)
            if correlated:
                actions.append(ResponseAction.ESCALATE_SOC)
                summary += " [CORRELATED with other threats]"
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=self._risk_to_severity(risk_level),
            confidence=risk_score,
            summary=summary,
            actions=list(dict.fromkeys(actions)),
            metadata={
                "user_id": user_id,
                "resource": resource,
                "access_allowed": access_allowed,
                "risk_level": risk_level.value,
                "risk_score": risk_score,
                "required_mfa": required_mfa,
                "is_privileged": is_privileged,
                "session_id": p.get("session_id", ""),
                "verification_results": {
                    "identity": identity_result,
                    "device": device_result,
                    "network": network_result,
                    "location": location_result,
                    "behavior": behavior_result,
                    "geo": geo_result,
                    "privilege": privilege_result,
                }
            }
        )
    
    async def _handle_identity_verification(self, event: ThreatEvent) -> AgentFinding:
        """Handle identity verification events"""
        p = event.payload
        user_id = p.get("user_id", "unknown")
        
        # Perform identity verification
        result = await self._verify_identity(user_id, p.get("auth_token"), p)
        
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        severity = Severity.MEDIUM
        
        if result.get("verified", False):
            summary = f"Identity verified for {user_id} (score: {result.get('confidence', 0):.2f})"
        else:
            summary = f"Identity verification FAILED for {user_id}: {result.get('reason', 'Unknown')}"
            actions.append(ResponseAction.REVOKE_IDENTITY)
            severity = Severity.HIGH
            self._blocked_attempts[user_id] += 1
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=result.get("confidence", 0.0),
            summary=summary,
            actions=actions,
            metadata={
                "user_id": user_id,
                "verified": result.get("verified", False),
                "reason": result.get("reason", ""),
                "risk_score": result.get("risk_score", 0.0),
            }
        )
    
    async def _handle_network_verification(self, event: ThreatEvent) -> AgentFinding:
        """Handle network verification (encrypted traffic, honeypot, etc.)"""
        p = event.payload
        src_ip = p.get("src_ip", "unknown")
        dst_ip = p.get("dst_ip", "unknown")
        dst_port = p.get("dst_port", 0)
        signature = p.get("signature", "")
        
        # Check for honeypot activity
        is_honeypot = await self._check_honeypot_access(src_ip, dst_ip, dst_port)
        
        # Check encrypted traffic patterns
        traffic_anomaly = await self._check_encrypted_traffic(p)
        
        # Check network segmentation
        segmentation_violation = await self._check_segmentation(src_ip, dst_ip, dst_port)
        
        risk_score = 0.0
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        severity = event.severity
        
        if is_honeypot:
            risk_score += 0.8
            actions.append(ResponseAction.ISOLATE_ASSET)
            actions.append(ResponseAction.ESCALATE_SOC)
            severity = Severity.CRITICAL
            summary = f"🚨 HONEYPOT ACCESS detected from {src_ip} to {dst_ip}:{dst_port}"
        
        elif traffic_anomaly.get("is_anomalous", False):
            risk_score += 0.4
            actions.append(ResponseAction.ISOLATE_ASSET)
            severity = Severity.HIGH
            summary = f"Traffic anomaly detected: {traffic_anomaly.get('reason', 'Unknown')}"
        
        elif segmentation_violation:
            risk_score += 0.3
            actions.append(ResponseAction.BLOCK_ACCESS)
            severity = Severity.HIGH
            summary = f"Network segmentation violation: {src_ip} -> {dst_ip}"
        
        else:
            summary = f"Network traffic verified: {src_ip} -> {dst_ip}:{dst_port}"
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=min(risk_score + 0.1, 1.0),
            summary=summary,
            actions=list(dict.fromkeys(actions)),
            metadata={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "is_honeypot": is_honeypot,
                "traffic_anomaly": traffic_anomaly,
                "segmentation_violation": segmentation_violation,
                "risk_score": risk_score,
            }
        )
    
    async def _handle_physical_verification(self, event: ThreatEvent) -> AgentFinding:
        """Handle physical access verification"""
        p = event.payload
        user_id = p.get("user_id", "unknown")
        zone = p.get("zone", "unknown")
        badge_scan = p.get("badge_scan", False)
        face_match = p.get("face_match", False)
        
        # Check if zone is restricted
        is_restricted = zone.lower() in self._config["restricted_zones"]
        
        # Check business hours
        hour = datetime.now(timezone.utc).hour
        is_business_hours = self._config["business_hours_start"] <= hour <= self._config["business_hours_end"]
        
        # Verify physical access
        risk_score = 0.0
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        severity = event.severity
        
        if is_restricted and (not badge_scan or not face_match):
            risk_score = 0.9
            actions.append(ResponseAction.LOCK_ZONE)
            actions.append(ResponseAction.NOTIFY_SECURITY)
            actions.append(ResponseAction.ESCALATE_SOC)
            severity = Severity.CRITICAL
            summary = f"🚨 UNAUTHORIZED PHYSICAL ACCESS to restricted zone: {zone} by {user_id}"
        
        elif not badge_scan or not face_match:
            risk_score = 0.5
            actions.append(ResponseAction.LOCK_ZONE)
            severity = Severity.HIGH
            summary = f"Physical access violation in {zone} by {user_id}"
        
        elif is_restricted and not is_business_hours:
            risk_score = 0.3
            actions.append(ResponseAction.NOTIFY_SECURITY)
            severity = Severity.MEDIUM
            summary = f"Physical access to restricted zone outside business hours: {zone} by {user_id}"
        
        else:
            summary = f"Physical access granted to {zone} by {user_id}"
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=risk_score,
            summary=summary,
            actions=list(dict.fromkeys(actions)),
            metadata={
                "user_id": user_id,
                "zone": zone,
                "is_restricted": is_restricted,
                "badge_scan": badge_scan,
                "face_match": face_match,
                "is_business_hours": is_business_hours,
                "risk_score": risk_score,
            }
        )
    
    async def _handle_behavioral_analysis(self, event: ThreatEvent) -> AgentFinding:
        """Handle behavioral analysis events"""
        p = event.payload
        user_id = p.get("user_id", "unknown")
        
        # Get behavioral profile
        profile = await self._get_behavioral_profile(user_id)
        
        # Analyze current behavior
        anomaly_score, details = await self._analyze_behavioral_anomaly(event, profile)
        
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        severity = Severity.MEDIUM
        
        if anomaly_score > 0.7:
            actions.append(ResponseAction.NOTIFY_SECURITY)
            actions.append(ResponseAction.ESCALATE_SOC)
            severity = Severity.HIGH
            summary = f"High behavioral anomaly detected for {user_id}: {details}"
        elif anomaly_score > 0.4:
            actions.append(ResponseAction.NOTIFY_SECURITY)
            severity = Severity.MEDIUM
            summary = f"Medium behavioral anomaly for {user_id}: {details}"
        else:
            summary = f"Behavioral profile normal for {user_id}"
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=anomaly_score,
            summary=summary,
            actions=actions,
            metadata={
                "user_id": user_id,
                "anomaly_score": anomaly_score,
                "details": details,
                "profile_exists": profile is not None,
            }
        )
    
    async def _handle_insider_threat(self, event: ThreatEvent) -> AgentFinding:
        """Handle insider threat detection"""
        p = event.payload
        user_id = p.get("user_id", "unknown")
        data_volume = p.get("unusual_data_volume_gb", 0)
        destination = p.get("destination", "unknown")
        
        risk_score = 0.0
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        severity = event.severity
        
        # Check data volume against baseline
        profile = await self._get_behavioral_profile(user_id)
        if profile and data_volume > profile.typical_data_volume * 2:
            risk_score = 0.6
            actions.append(ResponseAction.REVOKE_IDENTITY)
            severity = Severity.HIGH
            summary = f"Insider data transfer: {data_volume}GB by {user_id} to {destination}"
        
        # Check if transferring to suspicious destination
        elif destination in ["external_usb", "unknown_cloud", "personal_email"]:
            risk_score = 0.7
            actions.append(ResponseAction.REVOKE_IDENTITY)
            actions.append(ResponseAction.ISOLATE_ASSET)
            severity = Severity.HIGH
            summary = f"Data transfer to suspicious destination: {destination} by {user_id}"
        
        else:
            summary = f"Insider activity normal for {user_id}"
        
        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=risk_score,
            summary=summary,
            actions=actions,
            metadata={
                "user_id": user_id,
                "data_volume_gb": data_volume,
                "destination": destination,
                "risk_score": risk_score,
            }
        )
    
    # ============================================
    # Verification Methods
    # ============================================
    
    async def _verify_identity(self, user_id: str, auth_token: str, payload: Dict) -> Dict:
        """
        Verify user identity using multiple factors.
        Returns: {"verified": bool, "confidence": float, "risk_score": float, "reason": str}
        """
        result = {
            "verified": False,
            "confidence": 0.0,
            "risk_score": 0.0,
            "reason": "Identity verification failed"
        }
        
        # 1. Check auth token (if provided)
        if auth_token:
            token_valid = await self._validate_auth_token(user_id, auth_token)
            if token_valid:
                result["verified"] = True
                result["confidence"] = 0.8
                result["risk_score"] = 0.2
                result["reason"] = "Identity verified via auth token"
            else:
                result["reason"] = "Invalid auth token"
                return result
        
        # 2. Check biometric score
        biometric_score = payload.get("biometric_score", 0.0)
        if biometric_score > 0.7:
            result["verified"] = True
            result["confidence"] = max(result["confidence"], 0.9)
            result["risk_score"] = min(result["risk_score"], 0.1)
            result["reason"] = "Identity verified via biometrics"
        
        # 3. Check behavioral biometrics
        if payload.get("behavioral_pattern", {}):
            pattern_match = await self._verify_behavioral_biometrics(user_id, payload["behavioral_pattern"])
            if pattern_match:
                result["verified"] = True
                result["confidence"] = max(result["confidence"], 0.7)
                result["risk_score"] = min(result["risk_score"], 0.2)
                result["reason"] = "Identity verified via behavioral patterns"
        
        return result
    
    async def _verify_device(self, user_id: str, device_info: Dict, payload: Dict) -> Dict:
        """
        Verify device identity and health.
        Returns: {"verified": bool, "trust_score": float, "risk_score": float, "reason": str}
        """
        result = {
            "verified": False,
            "trust_score": 0.0,
            "risk_score": 0.5,
            "reason": "Device verification failed"
        }
        
        # 1. Check device fingerprint
        device_id = device_info.get("device_id")
        if device_id:
            # Generate fingerprint for comparison
            fingerprint = self._fingerprinter.get_fingerprint(device_id)
            
            # Check if device is in trusted devices
            if device_id in self._trusted_devices:
                trusted = self._trusted_devices[device_id]
                # Check if device matches stored fingerprint
                is_match, confidence, reason = self._fingerprinter.verify_fingerprint(
                    trusted, fingerprint
                )
                
                if is_match:
                    result["verified"] = True
                    result["trust_score"] = trusted.trust_score
                    result["risk_score"] = 0.1
                    result["reason"] = "Device verified and trusted"
                else:
                    result["risk_score"] = 0.7
                    result["reason"] = f"Device fingerprint mismatch: {reason}"
            
            else:
                # New device - require registration and MFA
                result["risk_score"] = 0.6
                result["reason"] = "New device - requires registration and MFA"
        
        # 2. Check device health
        health = device_info.get("health", {})
        health_checks = await self._check_device_health(health)
        
        if health_checks.get("is_healthy", False):
            result["trust_score"] = min(result["trust_score"] + 0.3, 1.0)
            if not result["verified"]:
                result["verified"] = True
                result["reason"] = "Device health verified"
        else:
            result["risk_score"] = min(result["risk_score"] + 0.3, 1.0)
            result["reason"] = f"Device health issues: {health_checks.get('issues', 'Unknown')}"
        
        return result
    
    async def _verify_network(self, network_info: Dict, payload: Dict) -> Dict:
        """
        Verify network security.
        Returns: {"is_secure": bool, "risk_score": float, "reason": str}
        """
        result = {
            "is_secure": False,
            "risk_score": 0.3,
            "reason": "Network verification failed"
        }
        
        # 1. Check if using VPN (expected)
        is_vpn = network_info.get("is_vpn", False)
        if is_vpn:
            result["risk_score"] = 0.1
            result["reason"] = "VPN connection verified"
        else:
            result["risk_score"] = 0.2
            result["reason"] = "No VPN - increased risk"
        
        # 2. Check network type
        network_type = network_info.get("type", "unknown")
        if network_type in ["corporate", "trusted"]:
            result["is_secure"] = True
            result["risk_score"] = max(0.0, result["risk_score"] - 0.2)
            result["reason"] = "Corporate network"
        elif network_type in ["public", "untrusted"]:
            result["risk_score"] = min(1.0, result["risk_score"] + 0.3)
            result["reason"] = "Public network - elevated risk"
        
        # 3. Check for known malicious IPs
        src_ip = payload.get("src_ip", "")
        if src_ip and await self._is_malicious_ip(src_ip):
            result["is_secure"] = False
            result["risk_score"] = 0.9
            result["reason"] = f"Malicious IP detected: {src_ip}"
        
        return result
    
    async def _verify_location(self, user_id: str, location_info: Dict, payload: Dict) -> Dict:
        """
        Verify user location.
        Returns: {"verified": bool, "risk_score": float, "reason": str}
        """
        result = {
            "verified": False,
            "risk_score": 0.3,
            "reason": "Location verification failed"
        }
        
        # 1. Check if location data is available
        if not location_info:
            result["risk_score"] = 0.4
            result["reason"] = "No location data available"
            return result
        
        # 2. Check if location is known/trusted
        claimed = location_info.get("claimed", "")
        detected = location_info.get("detected", "")
        lat = location_info.get("latitude")
        lon = location_info.get("longitude")
        
        # Check if location is in typical locations
        profile = await self._get_behavioral_profile(user_id)
        if profile and claimed in profile.typical_locations:
            result["verified"] = True
            result["risk_score"] = 0.1
            result["reason"] = "Location in typical profile"
        
        # Check if location is a restricted zone
        elif claimed in RESTRICTED_ZONES and not result["verified"]:
            result["risk_score"] = 0.5
            result["reason"] = "Restricted zone access - requires additional verification"
        
        # Check for location mismatch
        elif claimed and detected and claimed != detected:
            result["risk_score"] = 0.6
            result["reason"] = f"Location mismatch: {claimed} vs {detected}"
        
        else:
            result["risk_score"] = 0.3
            result["reason"] = "Location not in typical profile"
        
        return result
    
    async def _check_geo_velocity(self, user_id: str, location_info: Dict, timestamp: datetime) -> Dict:
        """
        Check for geo-velocity violations (impossible travel).
        Returns: {"is_violation": bool, "risk_score": float, "reason": str}
        """
        result = {
            "is_violation": False,
            "risk_score": 0.0,
            "reason": "Geo-velocity check passed"
        }
        
        # Get previous location for this user
        prev_location = await self._get_previous_location(user_id)
        if not prev_location:
            return result
        
        # Get current location
        current_lat = location_info.get("latitude")
        current_lon = location_info.get("longitude")
        
        if not current_lat or not current_lon:
            result["reason"] = "No valid location data"
            return result
        
        # Create GeoLocation objects
        loc1 = GeoLocation(
            latitude=prev_location["latitude"],
            longitude=prev_location["longitude"],
            timestamp=prev_location["timestamp"],
            location_name=prev_location.get("name", "")
        )
        loc2 = GeoLocation(
            latitude=current_lat,
            longitude=current_lon,
            timestamp=timestamp,
            location_name=location_info.get("claimed", "")
        )
        
        # Detect impossible travel
        is_impossible, risk_score, reason = self._geo_velocity.detect_impossible_travel(loc1, loc2)
        
        result["is_violation"] = is_impossible
        result["risk_score"] = risk_score
        result["reason"] = reason
        
        return result
    
    async def _check_behavioral_patterns(self, user_id: str, event: ThreatEvent) -> Dict:
        """
        Check behavioral patterns against profile.
        Returns: {"is_anomalous": bool, "risk_score": float, "reason": str}
        """
        result = {
            "is_anomalous": False,
            "risk_score": 0.0,
            "reason": "Behavioral patterns normal"
        }
        
        profile = await self._get_behavioral_profile(user_id)
        if not profile:
            result["risk_score"] = 0.2
            result["reason"] = "No behavioral profile - building baseline"
            return result
        
        anomaly_score, details = await self._analyze_behavioral_anomaly(event, profile)
        
        if anomaly_score > profile.anomaly_threshold:
            result["is_anomalous"] = True
            result["risk_score"] = anomaly_score
            result["reason"] = f"Behavioral anomaly detected: {details}"
        else:
            result["risk_score"] = anomaly_score * 0.5
            result["reason"] = "Behavior within normal range"
        
        return result
    
    async def _check_privileged_access(self, user_id: str, role: str, resource: str, event: ThreatEvent) -> Dict:
        """
        Check privileged access (JIT, PAM).
        Returns: {"is_allowed": bool, "risk_score": float, "reason": str}
        """
        result = {
            "is_allowed": False,
            "risk_score": 0.5,
            "reason": "Privileged access requires additional verification"
        }
        
        # 1. Check if user has valid privilege request
        if not await self._has_valid_privilege_request(user_id):
            result["reason"] = "No valid privilege request"
            return result
        
        # 2. Check time limits (JIT)
        if not await self._check_jit_limits(user_id):
            result["reason"] = "JIT access expired or not available"
            result["risk_score"] = 0.8
            return result
        
        # 3. Check if accessing sensitive resource
        if resource in RESTRICTED_ZONES:
            result["risk_score"] = 0.4
            result["reason"] = "Sensitive resource - additional verification required"
            return result
        
        # 4. Check data volume limits
        if event.payload.get("data_volume_gb", 0) > self._config["max_data_transfer_gb"]:
            result["risk_score"] = 0.7
            result["reason"] = "Data volume exceeds privileged access limits"
            return result
        
        # 5. All checks passed
        result["is_allowed"] = True
        result["risk_score"] = 0.1
        result["reason"] = "Privileged access granted (JIT)"
        
        return result
    
    async def _check_honeypot_access(self, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        """
        Check if traffic is hitting honeypot segments.
        """
        # This would typically check against a list of honeypot IPs/ranges
        # Simplified implementation
        honeypot_ips = {"192.168.99.0/24", "10.10.10.0/24"}
        
        # Check if destination IP is in honeypot range
        for hp_ip in honeypot_ips:
            if self._ip_in_network(dst_ip, hp_ip):
                log.warning(f"🚨 Honeypot access detected: {src_ip} -> {dst_ip}:{dst_port}")
                return True
        
        return False
    
    async def _check_encrypted_traffic(self, payload: Dict) -> Dict:
        """
        Analyze encrypted traffic patterns without decryption.
        """
        result = {
            "is_anomalous": False,
            "risk_score": 0.0,
            "reason": "Traffic pattern normal"
        }
        
        # Check data volume
        data_volume = payload.get("data_volume_gb", 0)
        if data_volume > self._config["max_data_transfer_gb"]:
            result["is_anomalous"] = True
            result["risk_score"] = 0.6
            result["reason"] = f"Excessive data transfer: {data_volume}GB"
            return result
        
        # Check time of day
        hour = datetime.now(timezone.utc).hour
        if hour < self._config["business_hours_start"] or hour > self._config["business_hours_end"]:
            result["risk_score"] = 0.3
            result["reason"] = "Traffic outside business hours"
        
        return result
    
    async def _check_segmentation(self, src_ip: str, dst_ip: str, dst_port: int) -> bool:
        """
        Check if traffic violates network segmentation.
        """
        # Simplified segmentation check
        # In production, this would check against security group rules
        sensitive_ports = {22, 3389, 5432, 3306, 27017}  # SSH, RDP, Postgres, MySQL, MongoDB
        
        # Check if source is from low-trust zone and destination is sensitive
        if dst_port in sensitive_ports:
            if self._is_low_trust_ip(src_ip):
                log.warning(f"⚠ Segmentation violation: {src_ip} -> {dst_ip}:{dst_port}")
                return True
        
        return False
    
    # ============================================
    # Behavioral Profile Methods
    # ============================================
    
    async def _get_behavioral_profile(self, user_id: str) -> Optional[BehavioralProfile]:
        """Get or create behavioral profile for user"""
        if user_id in self._behavioral_profiles:
            return self._behavioral_profiles[user_id]
        
        # Create new profile with default values
        profile = BehavioralProfile(
            user_id=user_id,
            typical_hours=[7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
            typical_locations=["office", "home", "vpn"],
            typical_devices=[],
            typical_data_volume=0.5,
            typical_apps=["email", "crm", "docs"],
            access_patterns=["email", "crm", "email"],
            anomaly_threshold=0.6,
            last_updated=datetime.now(timezone.utc),
            occurrences=0
        )
        self._behavioral_profiles[user_id] = profile
        return profile
    
    async def _update_behavioral_profile(self, user_id: str, event: ThreatEvent, risk_score: float):
        """Update behavioral profile with new data"""
        profile = await self._get_behavioral_profile(user_id)
        if not profile:
            return
        
        # Update typical hours
        hour = event.timestamp.hour
        if hour not in profile.typical_hours:
            profile.typical_hours.append(hour)
            profile.typical_hours = sorted(profile.typical_hours)[:12]  # Keep top 12 hours
        
        # Update typical locations
        p = event.payload
        location = p.get("location", {}).get("claimed", "")
        if location and location not in profile.typical_locations:
            profile.typical_locations.append(location)
            profile.typical_locations = profile.typical_locations[:5]  # Keep top 5
        
        # Update typical devices
        device_id = p.get("device_info", {}).get("device_id", "")
        if device_id and device_id not in profile.typical_devices:
            profile.typical_devices.append(device_id)
            profile.typical_devices = profile.typical_devices[:3]  # Keep top 3
        
        # Update access patterns
        resource = p.get("resource", "")
        if resource:
            profile.access_patterns.append(resource)
            profile.access_patterns = profile.access_patterns[-10:]  # Keep last 10
        
        # Update occurrence count
        profile.occurrences += 1
        profile.last_updated = datetime.now(timezone.utc)
        
        # Update risk score (moving average)
        profile.risk_score = (profile.risk_score * 0.7 + risk_score * 0.3)
    
    async def _analyze_behavioral_anomaly(self, event: ThreatEvent, profile: BehavioralProfile) -> Tuple[float, str]:
        """
        Analyze current behavior against profile.
        Returns: (anomaly_score, details)
        """
        anomaly_score = 0.0
        details = []
        
        p = event.payload
        
        # 1. Check time of day
        hour = event.timestamp.hour
        if hour not in profile.typical_hours:
            anomaly_score += 0.3
            details.append(f"Unusual hour: {hour}")
        
        # 2. Check location
        loc = p.get("location", {})
        if isinstance(loc, str):
            location = loc
        else:
            location = loc.get("claimed", "")
        if location and location not in profile.typical_locations:
            anomaly_score += 0.3
            details.append(f"Unusual location: {location}")
        
        # 3. Check device
        device_id = p.get("device_info", {}).get("device_id", "")
        if device_id and device_id not in profile.typical_devices:
            anomaly_score += 0.2
            details.append(f"New device: {device_id}")
        
        # 4. Check data volume
        data_volume = p.get("data_volume_gb", 0)
        if data_volume > profile.typical_data_volume * 2:
            anomaly_score += 0.2
            details.append(f"High data volume: {data_volume}GB")
        
        # 5. Check application access
        resource = p.get("resource", "")
        if resource and resource not in profile.typical_apps:
            anomaly_score += 0.2
            details.append(f"Unusual application: {resource}")
        
        # Normalize anomaly score
        anomaly_score = min(anomaly_score, 1.0)
        
        return anomaly_score, ", ".join(details)
    
    # ============================================
    # Device Health Methods
    # ============================================
    
    async def _check_device_health(self, health_info: Dict) -> Dict:
        """
        Check device health and posture.
        Returns: {"is_healthy": bool, "issues": List[str]}
        """
        issues = []
        
        # Check antivirus
        if not health_info.get("antivirus_active", False):
            issues.append("Antivirus inactive")
        
        # Check encryption
        if not health_info.get("disk_encrypted", False):
            issues.append("Disk not encrypted")
        
        # Check patches
        if health_info.get("patch_status", "up-to-date") != "up-to-date":
            issues.append("Missing patches")
        
        # Check firewall
        if not health_info.get("firewall_active", False):
            issues.append("Firewall inactive")
        
        # Check for root/jailbreak
        if health_info.get("rooted", False):
            issues.append("Device rooted/jailbroken")
        
        return {
            "is_healthy": len(issues) == 0,
            "issues": issues
        }
    
    # ============================================
    # Session Management
    # ============================================
    
    async def _create_session(self, user_id: str, device_info: Dict, risk_level: RiskLevel) -> str:
        """Create a new session for the user"""
        session_id = hashlib.sha256(
            f"{user_id}:{device_info.get('device_id', 'unknown')}:{datetime.now()}".encode()
        ).hexdigest()[:16]
        
        self._active_sessions[session_id] = {
            "user_id": user_id,
            "device_id": device_info.get("device_id", "unknown"),
            "created_at": datetime.now(timezone.utc),
            "last_verified": datetime.now(timezone.utc),
            "risk_level": risk_level,
            "is_active": True,
        }
        
        log.info(f"Session created: {session_id} for user {user_id}")
        return session_id
    
    async def _verify_session(self, session_id: str) -> bool:
        """Verify if session is still valid"""
        if session_id not in self._active_sessions:
            return False
        
        session = self._active_sessions[session_id]
        if not session["is_active"]:
            return False
        
        # Check timeout
        if (datetime.now(timezone.utc) - session["created_at"]).total_seconds() > self._config["session_timeout"]:
            return False
        
        # Check refresh
        if (datetime.now(timezone.utc) - session["last_verified"]).total_seconds() > self._config["session_refresh"]:
            session["last_verified"] = datetime.now(timezone.utc)
        
        return True
    
    # ============================================
    # Privileged Access Management (PAM)
    # ============================================
    
    async def _has_valid_privilege_request(self, user_id: str) -> bool:
        """Check if user has a valid privilege request"""
        # Simplified - would check against ticket/request system
        return True
    
    async def _check_jit_limits(self, user_id: str) -> bool:
        """Check JIT access time limits"""
        # Simplified - would check if access is within allowed time window
        return True
    
    # ============================================
    # Risk Scoring Methods
    # ============================================
    
    def _calculate_combined_risk_score(self, scores: Dict[str, float]) -> float:
        """Calculate combined risk score with weights"""
        combined_score = 0.0
        total_weight = 0.0
        
        for key, weight in RISK_WEIGHTS.items():
            if key in scores:
                combined_score += scores[key] * weight
                total_weight += weight
        
        if total_weight > 0:
            combined_score /= total_weight
        
        return min(combined_score, 1.0)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score"""
        if risk_score >= RISK_THRESHOLDS["critical"]:
            return RiskLevel.CRITICAL
        elif risk_score >= RISK_THRESHOLDS["high"]:
            return RiskLevel.HIGH
        elif risk_score >= RISK_THRESHOLDS["medium"]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _risk_to_severity(self, risk_level: RiskLevel) -> Severity:
        """Convert risk level to severity"""
        mapping = {
            RiskLevel.LOW: Severity.LOW,
            RiskLevel.MEDIUM: Severity.MEDIUM,
            RiskLevel.HIGH: Severity.HIGH,
            RiskLevel.CRITICAL: Severity.CRITICAL,
        }
        return mapping.get(risk_level, Severity.MEDIUM)
    
    # ============================================
    # Utility Methods
    # ============================================
    
    def _build_verification_summary(self, user_id: str, resource: str, access_allowed: bool,
                                   risk_level: RiskLevel, risk_score: float,
                                   identity: Dict, device: Dict, location: Dict,
                                   geo: Dict, privilege: Dict, required_mfa: List[str]) -> str:
        """Build a human-readable verification summary"""
        status = "✅ ALLOWED" if access_allowed else "⛔ BLOCKED"
        
        # Build MFA requirements string
        mfa_str = ", ".join(required_mfa) if required_mfa else "none"
        
        summary = (
            f"Zero Trust verification for {user_id} -> {resource}: {status} "
            f"(risk_level={risk_level.value}, score={risk_score:.2f}, "
            f"identity={identity.get('risk_score', 0):.2f}, "
            f"device={device.get('risk_score', 0):.2f}, "
            f"location={location.get('risk_score', 0):.2f}, "
            f"geo={geo.get('risk_score', 0):.2f}, "
            f"privilege={privilege.get('risk_score', 0):.2f}, "
            f"MFA=[{mfa_str}])"
        )
        
        if not access_allowed:
            summary += f" Reason: {identity.get('reason', 'Unknown')}"
        
        return summary
    
    async def _validate_auth_token(self, user_id: str, auth_token: str) -> bool:
        """Validate authentication token"""
        # Simplified - would validate JWT or other token
        return True
    
    async def _verify_behavioral_biometrics(self, user_id: str, pattern: Dict) -> bool:
        """Verify behavioral biometrics (typing speed, mouse patterns, etc.)"""
        # Simplified - would compare against stored behavioral patterns
        return True
    
    async def _is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known malicious"""
        # Simplified - would check against threat intelligence feeds
        return False
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network CIDR"""
        # Simplified - would use ipaddress module
        return False
    
    def _is_low_trust_ip(self, ip: str) -> bool:
        """Check if IP is from low-trust zone"""
        # Simplified - would check against IP ranges
        return False
    
    async def _get_previous_location(self, user_id: str) -> Optional[Dict]:
        """Get previous location for user"""
        # Simplified - would query from database
        return None
    
    async def _check_correlation(self, user_id: str, event: ThreatEvent, risk_level: RiskLevel) -> bool:
        """Check if this event correlates with other threats"""
        # Simplified - would check with correlation engine
        return False
    
    # ============================================
    # Background Tasks
    # ============================================
    
    async def start_zero_trust_monitoring(self) -> None:
        """Start background monitoring for Zero Trust"""
        log.info("Zero Trust monitoring started")
        
        while True:
            try:
                # 1. Clean expired sessions
                await self._clean_expired_sessions()
                
                # 2. Update device trust scores
                await self._update_device_trust_scores()
                
                # 3. Re-verify active sessions
                await self._reverify_active_sessions()
                
                await asyncio.sleep(60)  # Run every minute
            except Exception as e:
                log.error(f"Zero Trust monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _clean_expired_sessions(self) -> None:
        """Clean expired sessions"""
        now = datetime.now(timezone.utc)
        expired = []
        
        for session_id, session in self._active_sessions.items():
            if (now - session["created_at"]).total_seconds() > self._config["session_timeout"]:
                expired.append(session_id)
        
        for session_id in expired:
            del self._active_sessions[session_id]
            log.debug(f"Expired session cleaned: {session_id}")
    
    async def _update_device_trust_scores(self) -> None:
        """Update device trust scores"""
        # Simplified - would recalculate based on recent activity
        pass
    
    async def _reverify_active_sessions(self) -> None:
        """Re-verify active sessions"""
        for session_id, session in self._active_sessions.items():
            if not await self._verify_session(session_id):
                session["is_active"] = False
                log.warning(f"Session {session_id} invalidated during re-verification")