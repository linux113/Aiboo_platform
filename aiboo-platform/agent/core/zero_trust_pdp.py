"""
core/zero_trust_pdp.py — Zero Trust Policy Decision Point

The central decision-making engine for Zero Trust Layer 1.
Evaluates every access request against all available evidence
(identity, device, network, location, behavioral risk, threat intelligence)
and issues a decision: Allow, Deny, or Challenge with required actions.

Implements:
- Risk-based access decisions
- Adaptive MFA (step-up authentication)
- Just-In-Time (JIT) privilege escalation
- Session-bound continuous verification
- Policy enforcement based on dynamic context
"""

from __future__ import annotations

import asyncio
import logging
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from enum import Enum
from collections import defaultdict
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ThreatEvent, ThreatType, Severity, ResponseAction,
    AccessRequest, ZeroTrustDecision, RiskLevel,
    AgentFinding
)

log = logging.getLogger("ZeroTrustPDP")

# ============================================
# Policy Configuration
# ============================================

# Default risk thresholds
RISK_THRESHOLDS = {
    RiskLevel.LOW: 0.3,
    RiskLevel.MEDIUM: 0.5,
    RiskLevel.HIGH: 0.7,
    RiskLevel.CRITICAL: 0.9,
}

# MFA requirements per risk level
MFA_REQUIREMENTS = {
    RiskLevel.LOW: [],
    RiskLevel.MEDIUM: ["otp"],
    RiskLevel.HIGH: ["otp", "biometric"],
    RiskLevel.CRITICAL: ["otp", "biometric", "security_key"],
}

# Privileged access configuration
PRIVILEGED_ROLES = {"admin", "root", "superuser", "security_admin", "devops_admin"}
PRIVILEGE_JIT_DURATION_MINUTES = 15  # JIT access duration

# Session timeout (seconds)
SESSION_TIMEOUT = 3600  # 1 hour
SESSION_REFRESH_INTERVAL = 300  # 5 minutes


@dataclass
class PolicyContext:
    """
    Aggregated context for a single access request.
    Contains all evidence gathered from various sources.
    """
    request: AccessRequest
    identity_score: float = 0.0
    device_score: float = 0.0
    network_score: float = 0.0
    location_score: float = 0.0
    behavioral_score: float = 0.0
    geo_velocity_score: float = 0.0
    threat_intel_score: float = 0.0
    privilege_score: float = 0.0
    
    # Flags
    is_privileged: bool = False
    has_valid_token: bool = False
    device_trusted: bool = False
    location_verified: bool = False
    behavioral_anomaly: bool = False
    geo_velocity_violation: bool = False
    known_threat: bool = False
    
    # Additional metadata
    additional_data: Dict[str, Any] = field(default_factory=dict)


class ZeroTrustPDP:
    """
    Policy Decision Point for Zero Trust architecture.
    Makes access decisions based on dynamic risk assessment.
    """
    
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._running = False
        
        # State caches (TTLCache bounded)
        self._session_cache: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=3600)
        self._user_risk_cache: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        self._device_trust_cache: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        self._blacklist_cache: set = set()
        
        # Decision history (for audit and learning)
        self._decision_history: List[ZeroTrustDecision] = []
        
        # Recent access attempts (for rate limiting)
        self._recent_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self._rate_limit_window_seconds = 60
        self._max_attempts_per_window = 10
        
        # Configuration
        self._config = {
            "risk_thresholds": RISK_THRESHOLDS,
            "mfa_requirements": MFA_REQUIREMENTS,
            "privileged_roles": PRIVILEGED_ROLES,
            "jit_duration_minutes": PRIVILEGE_JIT_DURATION_MINUTES,
            "session_timeout": SESSION_TIMEOUT,
            "session_refresh": SESSION_REFRESH_INTERVAL,
        }
        
        log.info("ZeroTrustPDP initialized")
    
    def start(self) -> None:
        """Start the PDP - subscribe to relevant events"""
        self.bus.subscribe(AccessRequest, self._on_access_request)
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        
        self._running = True
        log.info("ZeroTrustPDP started — making access decisions")
    
    # ============================================
    # Event Handlers
    # ============================================
    
    async def _on_access_request(self, request: AccessRequest) -> None:
        """Handle an access request - evaluate and decide"""
        log.debug(f"PDP received access request: {request.user_id} -> {request.resource}")
        
        try:
            # Rate limit check
            if self._is_rate_limited(request.user_id):
                decision = self._create_decision(
                    request,
                    allowed=False,
                    risk_level=RiskLevel.CRITICAL,
                    actions=[ResponseAction.BLOCK_ACCESS, ResponseAction.ESCALATE_SOC],
                    reason="Rate limit exceeded - too many attempts",
                    confidence=1.0
                )
                await self.bus.publish(decision)
                return
            
            # Build policy context
            context = await self._build_policy_context(request)
            
            # Evaluate policy
            decision = await self._evaluate_policy(context)
            
            # Store decision
            self._decision_history.append(decision)
            if len(self._decision_history) > 10000:
                self._decision_history = self._decision_history[-5000:]
            
            # Publish decision
            await self.bus.publish(decision)
            
            # If allowed, track session
            if decision.allowed:
                session_id = await self._create_session(context)
                log.info(f"Access ALLOWED for {request.user_id} -> {request.resource} (session: {session_id})")
            else:
                log.warning(f"Access DENIED for {request.user_id} -> {request.resource}: {decision.reason}")
            
        except Exception as e:
            log.error(f"Error processing access request: {e}")
            # Fallback: deny access
            decision = self._create_decision(
                request,
                allowed=False,
                risk_level=RiskLevel.CRITICAL,
                actions=[ResponseAction.BLOCK_ACCESS, ResponseAction.ESCALATE_SOC],
                reason=f"PDP internal error: {str(e)}",
                confidence=0.5
            )
            await self.bus.publish(decision)
    
    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Listen to threat events to update risk state"""
        # Update blacklist if threat is confirmed
        if event.threat_type == ThreatType.NETWORK_INTRUSION and event.severity == Severity.CRITICAL:
            src_ip = event.payload.get("src_ip")
            if src_ip:
                self._blacklist_cache.add(src_ip)
                log.info(f"Added {src_ip} to blacklist")
        
        # Update user risk based on identity mismatches
        if event.threat_type == ThreatType.IDENTITY_MISMATCH:
            user_id = event.payload.get("user_id")
            if user_id:
                # Increase risk score
                current_risk = self._user_risk_cache.get(user_id, 0.0)
                new_risk = min(1.0, current_risk + 0.1)
                self._user_risk_cache[user_id] = new_risk
                log.debug(f"Updated risk for {user_id}: {new_risk:.2f}")
        
        # Update device trust on device health fail
        if event.threat_type == ThreatType.DEVICE_HEALTH_FAIL:
            device_id = event.payload.get("device_id")
            if device_id:
                self._device_trust_cache[device_id] = 0.0
                log.warning(f"Device {device_id} trust set to 0 (health fail)")
    
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings to update risk state"""
        # If an agent flagged a high-confidence threat, adjust risks
        if finding.confidence > 0.8 and finding.severity in (Severity.HIGH, Severity.CRITICAL):
            # Extract entity
            entity_id = finding.metadata.get("user_id") or finding.metadata.get("src_ip")
            if entity_id:
                current_risk = self._user_risk_cache.get(entity_id, 0.0)
                new_risk = min(1.0, current_risk + 0.15 * finding.confidence)
                self._user_risk_cache[entity_id] = new_risk
                log.info(f"Updated risk for {entity_id} to {new_risk:.2f} based on {finding.agent_name}")
    
    # ============================================
    # Policy Evaluation
    # ============================================
    
    async def _build_policy_context(self, request: AccessRequest) -> PolicyContext:
        """Gather all evidence and build evaluation context"""
        context = PolicyContext(request=request)
        
        # 1. Identity score (from request or cache)
        context.identity_score = request.risk_score if request.risk_score > 0 else 0.2
        
        # 2. Device trust (from cache)
        device_id = request.device_id
        if device_id:
            context.device_score = self._device_trust_cache.get(device_id, 0.5)
            context.device_trusted = context.device_score > 0.7
        
        # 3. User risk (from cache)
        user_id = request.user_id
        if user_id:
            context.behavioral_score = self._user_risk_cache.get(user_id, 0.2)
        
        # 4. Location verification (from request location)
        if request.location:
            # Simplified: if location is in trusted list, lower risk
            trusted_locations = {"office", "home", "vpn", "corporate"}
            if request.location in trusted_locations:
                context.location_verified = True
                context.location_score = 0.1
            else:
                context.location_score = 0.6
        
        # 5. Network verification
        if request.network:
            trusted_networks = {"corporate", "vpn", "trusted"}
            if request.network in trusted_networks:
                context.network_score = 0.1
            else:
                context.network_score = 0.5
        
        # 6. Geo-velocity (would be computed elsewhere)
        # For now, assume no violation
        context.geo_velocity_score = 0.0
        
        # 7. Threat intel - check blacklist
        if user_id in self._blacklist_cache or device_id in self._blacklist_cache:
            context.known_threat = True
            context.threat_intel_score = 1.0
        
        # 8. Privilege check
        role = request.behavior_context.get("role", "user")
        if role.lower() in self._config["privileged_roles"]:
            context.is_privileged = True
            context.privilege_score = 0.3  # baseline for privileged users
        
        # 9. Behavioral anomaly flag (from behavioral engine if available)
        # This would be set by BehavioralDNAEngine via events, but for now we use cache
        
        return context
    
    async def _evaluate_policy(self, context: PolicyContext) -> ZeroTrustDecision:
        """
        Evaluate policy based on aggregated context.
        Returns a ZeroTrustDecision.
        """
        request = context.request
        
        # 1. Quick block: known threat
        if context.known_threat or context.threat_intel_score > 0.8:
            return self._create_decision(
                request,
                allowed=False,
                risk_level=RiskLevel.CRITICAL,
                actions=[ResponseAction.BLOCK_ACCESS, ResponseAction.ESCALATE_SOC, 
                        ResponseAction.NOTIFY_SECURITY],
                reason="Known threat detected - access blocked",
                confidence=context.threat_intel_score
            )
        
        # 2. Quick block: blacklisted entity
        if request.user_id in self._blacklist_cache or request.device_id in self._blacklist_cache:
            return self._create_decision(
                request,
                allowed=False,
                risk_level=RiskLevel.CRITICAL,
                actions=[ResponseAction.BLOCK_ACCESS, ResponseAction.ESCALATE_SOC],
                reason="Entity blacklisted - access denied",
                confidence=0.95
            )
        
        # 3. Calculate overall risk score
        risk_score = self._calculate_risk_score(context)
        risk_level = self._score_to_risk_level(risk_score)
        
        # 4. Determine required actions
        actions = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        allowed = False
        
        # 5. Make decision based on risk level
        if risk_level == RiskLevel.LOW:
            allowed = True
            # Low risk - no extra actions
            reason = "Low risk - access granted"
            
        elif risk_level == RiskLevel.MEDIUM:
            # Medium risk - require OTP
            actions.append(ResponseAction.CHALLENGE_MFA)
            actions.append(ResponseAction.STEP_UP_AUTH)
            # Allow after MFA challenge
            allowed = True
            reason = "Medium risk - MFA required"
            
        elif risk_level == RiskLevel.HIGH:
            # High risk - require full MFA + biometric
            actions.extend([
                ResponseAction.CHALLENGE_MFA,
                ResponseAction.STEP_UP_AUTH,
                ResponseAction.NOTIFY_SECURITY
            ])
            # Allow only if MFA succeeds (we assume it will)
            allowed = True
            reason = "High risk - step-up authentication required"
            
        else:  # CRITICAL
            # Critical risk - block by default
            allowed = False
            actions.extend([
                ResponseAction.BLOCK_ACCESS,
                ResponseAction.FORCE_LOGOUT,
                ResponseAction.REVOKE_IDENTITY,
                ResponseAction.ESCALATE_SOC,
                ResponseAction.NOTIFY_SECURITY
            ])
            reason = "Critical risk - access blocked"
        
        # 6. Privileged access handling
        if context.is_privileged and allowed:
            # JIT: grant temporary privilege
            actions.append(ResponseAction.GRANT_TEMP_PRIVILEGE)
            actions.append(ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION)
            reason += " (JIT privilege granted)"
        
        # 7. Device quarantine if device score is low but not blocked
        if context.device_score < 0.3 and allowed:
            actions.append(ResponseAction.QUARANTINE_DEVICE)
            reason += " (device quarantined)"
        
        # 8. If geo-velocity violation, force MFA even if low risk
        if context.geo_velocity_score > 0.6:
            if ResponseAction.CHALLENGE_MFA not in actions:
                actions.append(ResponseAction.CHALLENGE_MFA)
                actions.append(ResponseAction.STEP_UP_AUTH)
            reason += " (geo-velocity anomaly - MFA enforced)"
        
        # 9. Deduplicate actions
        actions = list(dict.fromkeys(actions))
        
        # 10. Create decision
        decision = self._create_decision(
            request,
            allowed=allowed,
            risk_level=risk_level,
            actions=actions,
            reason=reason,
            confidence=risk_score,
            context=context
        )
        
        return decision
    
    def _calculate_risk_score(self, context: PolicyContext) -> float:
        """
        Calculate overall risk score from context using weighted factors.
        """
        weights = {
            "identity": 0.25,
            "device": 0.20,
            "network": 0.15,
            "location": 0.15,
            "behavioral": 0.15,
            "threat_intel": 0.10,
        }
        
        scores = {
            "identity": context.identity_score,
            "device": context.device_score,
            "network": context.network_score,
            "location": context.location_score,
            "behavioral": context.behavioral_score,
            "threat_intel": context.threat_intel_score,
        }
        
        # Add geo-velocity penalty
        geo_penalty = context.geo_velocity_score * 0.2  # extra penalty
        
        # Calculate weighted sum
        total = 0.0
        for key, weight in weights.items():
            total += scores.get(key, 0.0) * weight
        
        total += geo_penalty
        total = min(total, 1.0)
        
        # If privileged, slightly increase risk (because privileged access is more dangerous)
        if context.is_privileged:
            total = min(1.0, total + 0.05)
        
        return total
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to RiskLevel"""
        thresholds = self._config["risk_thresholds"]
        if score >= thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _create_decision(self, request: AccessRequest, allowed: bool,
                        risk_level: RiskLevel, actions: List[ResponseAction],
                        reason: str, confidence: float,
                        context: Optional[PolicyContext] = None) -> ZeroTrustDecision:
        """Create a ZeroTrustDecision object"""
        return ZeroTrustDecision(
            request_id=request.session_id or f"req_{hashlib.md5(request.user_id.encode()).hexdigest()[:8]}",
            allowed=allowed,
            risk_level=risk_level,
            required_actions=actions,
            reason=reason,
            confidence=confidence,
            timestamp=datetime.now(timezone.utc)
        )
    
    # ============================================
    # Session Management
    # ============================================
    
    async def _create_session(self, context: PolicyContext) -> str:
        """Create a session for the allowed access"""
        session_id = hashlib.sha256(
            f"{context.request.user_id}:{context.request.device_id}:{datetime.now()}".encode()
        ).hexdigest()[:16]
        
        session_data = {
            "user_id": context.request.user_id,
            "device_id": context.request.device_id,
            "resource": context.request.resource,
            "created_at": datetime.now(timezone.utc),
            "last_verified": datetime.now(timezone.utc),
            "risk_level": self._score_to_risk_level(
                self._calculate_risk_score(context)
            ),
            "is_active": True,
        }
        self._session_cache[session_id] = session_data
        return session_id
    
    def _is_rate_limited(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._rate_limit_window_seconds)
        attempts = [t for t in self._recent_attempts[user_id] if t > cutoff]
        self._recent_attempts[user_id] = attempts
        attempts.append(now)
        return len(attempts) > self._max_attempts_per_window
    
    # ============================================
    # Public Query Methods
    # ============================================
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data by ID"""
        return self._session_cache.get(session_id)
    
    def verify_session(self, session_id: str) -> bool:
        """Check if session is still valid"""
        session = self._session_cache.get(session_id)
        if not session or not session.get("is_active"):
            return False
        
        # Check timeout
        created_at = session.get("created_at")
        if created_at:
            elapsed = (datetime.now(timezone.utc) - created_at).total_seconds()
            if elapsed > self._config["session_timeout"]:
                return False
        
        # Check refresh
        last_verified = session.get("last_verified")
        if last_verified:
            elapsed = (datetime.now(timezone.utc) - last_verified).total_seconds()
            if elapsed > self._config["session_refresh"]:
                # Need to re-verify
                session["last_verified"] = datetime.now(timezone.utc)
                # In real implementation, would trigger re-verification
        
        return True
    
    def get_decision_history(self, limit: int = 100) -> List[ZeroTrustDecision]:
        """Get recent decisions for audit"""
        return self._decision_history[-limit:]
    
    def get_user_risk(self, user_id: str) -> float:
        """Get current risk score for a user"""
        return self._user_risk_cache.get(user_id, 0.0)
    
    def get_device_trust(self, device_id: str) -> float:
        """Get trust score for a device"""
        return self._device_trust_cache.get(device_id, 0.5)
    
    def update_user_risk(self, user_id: str, risk_score: float) -> None:
        """Update risk score for a user (called by other components)"""
        self._user_risk_cache[user_id] = min(1.0, max(0.0, risk_score))
    
    def update_device_trust(self, device_id: str, trust_score: float) -> None:
        """Update trust score for a device"""
        self._device_trust_cache[device_id] = min(1.0, max(0.0, trust_score))
    
    def blacklist_entity(self, entity: str) -> None:
        """Add entity to blacklist (user, device, IP)"""
        self._blacklist_cache.add(entity)
        log.warning(f"Entity blacklisted: {entity}")
    
    def unblacklist_entity(self, entity: str) -> None:
        """Remove entity from blacklist"""
        if entity in self._blacklist_cache:
            self._blacklist_cache.remove(entity)
            log.info(f"Entity removed from blacklist: {entity}")
    
    # ============================================
    # Utility Methods
    # ============================================
    
    def get_config(self) -> Dict:
        """Get current configuration"""
        return self._config.copy()
    
    def update_config(self, new_config: Dict) -> None:
        """Update configuration (partial updates allowed)"""
        self._config.update(new_config)
        log.info("PDP configuration updated")
    
    def stop(self) -> None:
        """Stop the PDP"""
        self._running = False
        log.info("ZeroTrustPDP stopped")