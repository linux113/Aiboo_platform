"""
core/zero_trust_pep.py — Zero Trust Policy Enforcement Point

The enforcement gatekeeper for Zero Trust Layer 1.
Executes decisions made by the PDP:
- Allow/Block access
- Challenge MFA
- Revoke sessions
- Quarantine devices
- Enforce JIT privilege grants/revocations
- Isolate assets
- Notify security teams

Acts as the "muscle" behind the Zero Trust architecture.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Callable, Coroutine
from collections import defaultdict
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ZeroTrustDecision, ResponseAction, RiskLevel,
    ThreatEvent, ThreatType, Severity, AgentFinding
)

log = logging.getLogger("ZeroTrustPEP")

# ============================================
# Configuration
# ============================================

# Default time to keep enforcement logs
ENFORCEMENT_LOG_TTL_DAYS = 7

# JIT privilege duration
JIT_DURATION_MINUTES = 15

# Session cleanup interval (seconds)
SESSION_CLEANUP_INTERVAL = 60


class ZeroTrustPEP:
    """
    Policy Enforcement Point for Zero Trust architecture.
    Executes actions based on PDP decisions.
    """
    
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._running = False
        
        # Action handlers registry
        self._action_handlers: Dict[ResponseAction, Callable] = {
            ResponseAction.ALLOW_ACCESS: self._allow_access,
            ResponseAction.BLOCK_ACCESS: self._block_access,
            ResponseAction.CHALLENGE_MFA: self._challenge_mfa,
            ResponseAction.REVOKE_SESSION: self._revoke_session,
            ResponseAction.QUARANTINE_DEVICE: self._quarantine_device,
            ResponseAction.FORCE_LOGOUT: self._force_logout,
            ResponseAction.STEP_UP_AUTH: self._step_up_auth,
            ResponseAction.GRANT_TEMP_PRIVILEGE: self._grant_temp_privilege,
            ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION: self._schedule_privilege_revocation,
            ResponseAction.ISOLATE_ASSET: self._isolate_asset,
            ResponseAction.REVOKE_IDENTITY: self._revoke_identity,
            ResponseAction.NOTIFY_SECURITY: self._notify_security,
            ResponseAction.ESCALATE_SOC: self._escalate_soc,
            ResponseAction.PSEUDO_LOCK: self._pseudo_lock,
            ResponseAction.LOCK_ZONE: self._lock_zone,
            ResponseAction.LOG: self._log_only,
            ResponseAction.ALERT_DASHBOARD: self._alert_dashboard,
        }
        
        # Enforcement state (TTLCache bounded)
        self._enforced_sessions: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400)
        self._quarantined_devices: set = set()
        self._active_privileges: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=3600)
        self._enforcement_history: List[Dict] = []
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._privilege_revocation_task: Optional[asyncio.Task] = None
        
        # Action execution tracking (for dedup)
        self._recent_actions: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=60)
        self._action_dedup_window_seconds = 5
        
        log.info("ZeroTrustPEP initialized")
    
    def start(self) -> None:
        """Start the PEP - subscribe to decisions and start background tasks"""
        self.bus.subscribe(ZeroTrustDecision, self._on_decision)
        # Also listen to AgentFindings for enforcement triggers
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        
        self._running = True
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._session_cleanup_loop())
        self._privilege_revocation_task = asyncio.create_task(self._privilege_revocation_loop())
        
        log.info("ZeroTrustPEP started — enforcing decisions")
    
    # ============================================
    # Decision Handler
    # ============================================
    
    async def _on_decision(self, decision: ZeroTrustDecision) -> None:
        """Process a ZeroTrustDecision and execute required actions"""
        log.debug(f"PEP processing decision: {decision.request_id} -> {decision.allowed}")
        
        # Execute each action in the decision
        for action in decision.required_actions:
            handler = self._action_handlers.get(action)
            if handler:
                try:
                    # Deduplicate if same action on same entity within window
                    dedup_key = f"{action.value}:{decision.request_id}"
                    if dedup_key in self._recent_actions:
                        elapsed = (datetime.now(timezone.utc) - self._recent_actions[dedup_key]).total_seconds()
                        if elapsed < self._action_dedup_window_seconds:
                            log.debug(f"Skipping duplicate action: {action.value} for {decision.request_id}")
                            continue
                    
                    await handler(decision)
                    self._recent_actions[dedup_key] = datetime.now(timezone.utc)
                    
                    # Log enforcement
                    self._enforcement_history.append({
                        "request_id": decision.request_id,
                        "action": action.value,
                        "timestamp": datetime.now(timezone.utc),
                        "decision": decision.allowed,
                        "risk_level": decision.risk_level.value,
                    })
                    if len(self._enforcement_history) > 10000:
                        self._enforcement_history = self._enforcement_history[-5000:]
                    
                except Exception as e:
                    log.error(f"Action {action.value} failed: {e}")
            else:
                log.warning(f"No handler for action: {action}")
        
        # If decision is deny, also track for metrics
        if not decision.allowed:
            self._enforced_sessions[decision.request_id] = {
                "status": "denied",
                "timestamp": datetime.now(timezone.utc),
                "reason": decision.reason,
                "risk_level": decision.risk_level.value,
            }
        
        # Log significant actions
        if not decision.allowed or decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            log.warning(
                f"ENFORCED: {decision.request_id} -> {decision.reason} (risk={decision.risk_level.value}, actions={[a.value for a in decision.required_actions]})"
            )
    
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """React to agent findings (e.g., confirmed threats)"""
        # If agent reports a critical finding, we may enforce additional actions
        if finding.severity == Severity.CRITICAL and finding.confidence > 0.8:
            # Extract entity
            entity_id = finding.metadata.get("user_id") or finding.metadata.get("src_ip")
            if entity_id and ResponseAction.QUARANTINE_DEVICE in finding.actions:
                # Enforce quarantine even without explicit decision
                # This is a safety net: agents can trigger direct enforcement
                if not await self._check_if_already_enforced(entity_id, "quarantine"):
                    await self._quarantine_entity(entity_id, finding.summary)
    
    # ============================================
    # Action Handlers
    # ============================================
    
    async def _allow_access(self, decision: ZeroTrustDecision) -> None:
        """Grant access to the requested resource"""
        # In real implementation, this would integrate with access control systems
        # For now, log it and update session state
        log.info(f"[ALLOW] Access granted for {decision.request_id}")
        # Mark session as active
        self._enforced_sessions[decision.request_id] = {
            "status": "active",
            "granted_at": datetime.now(timezone.utc),
            "risk_level": decision.risk_level.value,
        }
    
    async def _block_access(self, decision: ZeroTrustDecision) -> None:
        """Block access to the requested resource"""
        log.warning(f"[BLOCK] Access blocked for {decision.request_id}: {decision.reason}")
        # Update session state
        self._enforced_sessions[decision.request_id] = {
            "status": "blocked",
            "blocked_at": datetime.now(timezone.utc),
            "reason": decision.reason,
        }
        # Could also integrate with firewall/API gateway
        # e.g., add temporary deny rule in WAF or API gateway
    
    async def _challenge_mfa(self, decision: ZeroTrustDecision) -> None:
        """Trigger MFA challenge for the user"""
        log.warning(f"[MFA] Challenging user for {decision.request_id}")
        # In production, this would send OTP via SMS/App, call biometric challenge, etc.
        # For now, we just log and could simulate a challenge response
        # We can also publish an event to trigger a callback
        challenge_event = ThreatEvent(
            source="ZeroTrustPEP",
            threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.MEDIUM,
            payload={
                "request_id": decision.request_id,
                "action": "mfa_challenge",
                "required_factors": ["otp"],
                "expires_in": 60,  # seconds
            }
        )
        await self.bus.publish(challenge_event)
    
    async def _revoke_session(self, decision: ZeroTrustDecision) -> None:
        """Revoke an active session"""
        log.warning(f"[REVOKE] Session revoked for {decision.request_id}")
        # Remove session from active store
        if decision.request_id in self._enforced_sessions:
            self._enforced_sessions[decision.request_id]["status"] = "revoked"
        # In real implementation, call IdP to invalidate tokens
        # Also force logout all devices for that user
        user_id = self._extract_user_id_from_decision(decision)
        if user_id:
            # Invalidate all sessions for this user
            for sid in list(self._enforced_sessions.keys()):
                if self._enforced_sessions[sid].get("user_id") == user_id:
                    self._enforced_sessions[sid]["status"] = "revoked"
            log.info(f"All sessions revoked for user {user_id}")
    
    async def _quarantine_device(self, decision: ZeroTrustDecision) -> None:
        """Quarantine a compromised device"""
        device_id = self._extract_device_id_from_decision(decision)
        if device_id:
            self._quarantined_devices.add(device_id)
            log.warning(f"[QUARANTINE] Device {device_id} quarantined")
            # In production: add to quarantine list in network ACL, block traffic, etc.
            # Could also push to MDM to lock device
        else:
            log.warning(f"[QUARANTINE] No device ID found for {decision.request_id}")
    
    async def _force_logout(self, decision: ZeroTrustDecision) -> None:
        """Force logout the user from all sessions"""
        user_id = self._extract_user_id_from_decision(decision)
        log.warning(f"[FORCE_LOGOUT] Force logout for user {user_id or decision.request_id}")
        # In real implementation: call IdP to invalidate all tokens
        # For now, mark all sessions for this user as revoked
        if user_id:
            for sid in list(self._enforced_sessions.keys()):
                if self._enforced_sessions[sid].get("user_id") == user_id:
                    self._enforced_sessions[sid]["status"] = "revoked"
    
    async def _step_up_auth(self, decision: ZeroTrustDecision) -> None:
        """Require step-up authentication (stronger MFA)"""
        log.warning(f"[STEP_UP] Step-up auth required for {decision.request_id}")
        # Similar to challenge_mfa but with higher assurance level
        step_up_event = ThreatEvent(
            source="ZeroTrustPEP",
            threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.HIGH,
            payload={
                "request_id": decision.request_id,
                "action": "step_up_auth",
                "required_factors": ["otp", "biometric"],
                "expires_in": 30,
            }
        )
        await self.bus.publish(step_up_event)
    
    async def _grant_temp_privilege(self, decision: ZeroTrustDecision) -> None:
        """Grant Just-In-Time (JIT) privileged access"""
        user_id = self._extract_user_id_from_decision(decision)
        if not user_id:
            return
        
        duration_minutes = JIT_DURATION_MINUTES
        expiry = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        
        self._active_privileges[user_id] = {
            "granted_at": datetime.now(timezone.utc),
            "expires_at": expiry,
            "duration_minutes": duration_minutes,
            "request_id": decision.request_id,
            "risk_level": decision.risk_level.value,
        }
        log.warning(f"[PRIVILEGE] JIT privilege granted to {user_id} for {duration_minutes}min")
        # In production: elevate permissions in IAM system
        # Also create audit record
    
    async def _schedule_privilege_revocation(self, decision: ZeroTrustDecision) -> None:
        """Schedule privilege revocation after JIT window"""
        # This is handled by the background loop; we just log it
        user_id = self._extract_user_id_from_decision(decision)
        if user_id and user_id in self._active_privileges:
            log.info(f"[PRIVILEGE] Scheduled revocation for {user_id} at {self._active_privileges[user_id]['expires_at']}")
        # The background loop will actually revoke
    
    async def _isolate_asset(self, decision: ZeroTrustDecision) -> None:
        """Isolate an asset (network isolation)"""
        log.warning(f"[ISOLATE] Asset isolated for {decision.request_id}")
        # In production: apply network ACLs, update security groups, etc.
        # Could use SDN controller or cloud API
        # For now, just log and maybe call Windows netsh if applicable
        try:
            # Example: block IP via Windows firewall (if running on Windows)
            if self._is_windows():
                # In a real implementation, we'd extract the IP from decision
                ip = self._extract_ip_from_decision(decision)
                if ip:
                    import subprocess
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=AiBoO_Isolate_{ip}", "dir=in", f"remoteip={ip}",
                        "action=block", "protocol=any"
                    ]
                    subprocess.run(cmd, capture_output=True, timeout=10)
        except Exception as e:
            log.error(f"Error in asset isolation: {e}")
    
    async def _revoke_identity(self, decision: ZeroTrustDecision) -> None:
        """Revoke identity credentials"""
        user_id = self._extract_user_id_from_decision(decision)
        log.warning(f"[REVOKE_IDENTITY] Identity revoked for {user_id or decision.request_id}")
        # In production: disable account, revoke tokens, etc.
        # Also force logout
        if user_id:
            await self._force_logout(decision)
    
    async def _notify_security(self, decision: ZeroTrustDecision) -> None:
        """Send security notification (email/SMS/Slack)"""
        log.warning(f"[NOTIFY] Security team notified for {decision.request_id}: {decision.reason}")
        # In production: send to PagerDuty, Slack, email, etc.
        # For now, just log with high visibility
        alert_msg = f"[SECURITY ALERT] {decision.request_id} - {decision.reason}"
        log.warning("%s", alert_msg)
    
    async def _escalate_soc(self, decision: ZeroTrustDecision) -> None:
        """Escalate to SOC (Security Operations Center)"""
        log.critical(f"[ESCALATE] SOC escalation for {decision.request_id}: {decision.reason}")
        # In production: create Jira/Servicenow ticket, trigger playbook
        # For now, just log with high severity
    
    async def _pseudo_lock(self, decision: ZeroTrustDecision) -> None:
        """Apply Pseudo-Lock (honeypot diversion)"""
        log.warning(f"[PSEUDO_LOCK] Pseudo-lock applied for {decision.request_id}")
        # This is already handled by PseudoLockAgent; we just log it here
        # Could also trigger additional decoy deployment
    
    async def _lock_zone(self, decision: ZeroTrustDecision) -> None:
        """Lock a physical zone"""
        log.warning(f"[LOCK_ZONE] Zone locked for {decision.request_id}")
        # In production: call access control system to lock doors/gates
    
    async def _log_only(self, decision: ZeroTrustDecision) -> None:
        """Just log the decision (no action)"""
        log.info(f"[LOG] {decision.request_id}: {decision.reason}")
    
    async def _alert_dashboard(self, decision: ZeroTrustDecision) -> None:
        """Send alert to dashboard (already handled by CommandDashboard)"""
        # The dashboard subscribes directly to decisions, so this is a no-op here
        # But we keep it for completeness
        pass
    
    # ============================================
    # Background Tasks
    # ============================================
    
    async def _session_cleanup_loop(self) -> None:
        """Periodically clean up expired sessions and enforcements"""
        while self._running:
            await asyncio.sleep(SESSION_CLEANUP_INTERVAL)
            try:
                now = datetime.now(timezone.utc)
                expired = []
                for sid, state in self._enforced_sessions.items():
                    # If session is older than 1 day, mark expired
                    created = state.get("granted_at") or state.get("blocked_at")
                    if created and (now - created).total_seconds() > 86400:  # 24 hours
                        expired.append(sid)
                    # Also remove revoked sessions after 1 hour
                    if state.get("status") == "revoked":
                        if created and (now - created).total_seconds() > 3600:
                            expired.append(sid)
                for sid in expired:
                    del self._enforced_sessions[sid]
                if expired:
                    log.debug(f"Cleaned up {len(expired)} expired sessions")
            except Exception as e:
                log.error(f"Session cleanup error: {e}")
    
    async def _privilege_revocation_loop(self) -> None:
        """Periodically revoke expired JIT privileges"""
        while self._running:
            await asyncio.sleep(30)  # Check every 30 seconds
            try:
                now = datetime.now(timezone.utc)
                expired_users = []
                for user_id, grant in self._active_privileges.items():
                    expires_at = grant.get("expires_at")
                    if expires_at and now >= expires_at:
                        expired_users.append(user_id)
                
                for user_id in expired_users:
                    # Revoke privilege
                    del self._active_privileges[user_id]
                    log.warning(f"[PRIVILEGE] JIT privilege revoked for {user_id} (expired)")
                    # In production: call IAM to remove elevated permissions
                    # Also publish event
                    revoke_event = ThreatEvent(
                        source="ZeroTrustPEP",
                        threat_type=ThreatType.IDENTITY_MISMATCH,
                        severity=Severity.MEDIUM,
                        payload={
                            "user_id": user_id,
                            "action": "privilege_revoked",
                            "reason": "JIT expiration",
                        }
                    )
                    await self.bus.publish(revoke_event)
            except Exception as e:
                log.error(f"Privilege revocation error: {e}")
    
    # ============================================
    # Helper Methods
    # ============================================
    
    def _extract_user_id_from_decision(self, decision: ZeroTrustDecision) -> Optional[str]:
        """Extract user ID from decision context (if available)"""
        # Since ZeroTrustDecision doesn't have user_id directly, we need to use request_id
        # Could be encoded in request_id or stored in state
        # For simplicity, we can check if request_id is a user_id pattern
        # In real implementation, PEP would have access to the original request via correlation
        # We store user_id in session state
        if decision.request_id in self._enforced_sessions:
            return self._enforced_sessions[decision.request_id].get("user_id")
        return None
    
    def _extract_device_id_from_decision(self, decision: ZeroTrustDecision) -> Optional[str]:
        """Extract device ID from decision context"""
        # Similar to user extraction
        if decision.request_id in self._enforced_sessions:
            return self._enforced_sessions[decision.request_id].get("device_id")
        return None
    
    def _extract_ip_from_decision(self, decision: ZeroTrustDecision) -> Optional[str]:
        """Extract source IP from decision context"""
        # Stored in session state
        if decision.request_id in self._enforced_sessions:
            return self._enforced_sessions[decision.request_id].get("src_ip")
        return None
    
    async def _quarantine_entity(self, entity_id: str, reason: str) -> None:
        """Direct quarantine of entity (used by agent findings)"""
        if entity_id.startswith("device_"):
            self._quarantined_devices.add(entity_id)
            log.warning(f"[DIRECT] Device {entity_id} quarantined: {reason}")
        elif entity_id.startswith("user_"):
            # Could also quarantine user by revoking identity
            log.warning(f"[DIRECT] User {entity_id} flagged: {reason}")
    
    async def _check_if_already_enforced(self, entity_id: str, action: str) -> bool:
        """Check if entity already has this action enforced"""
        if action == "quarantine":
            return entity_id in self._quarantined_devices
        return False
    
    def _is_windows(self) -> bool:
        """Check if running on Windows"""
        import sys
        return sys.platform == "win32"
    
    # ============================================
    # Public Query Methods
    # ============================================
    
    def get_enforcement_status(self, request_id: str) -> Optional[Dict]:
        """Get status of an enforcement"""
        return self._enforced_sessions.get(request_id)
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active sessions"""
        return [{"id": sid, "data": state} for sid, state in self._enforced_sessions.items()
                if state.get("status") == "active"]
    
    def get_quarantined_devices(self) -> List[str]:
        """Get list of quarantined devices"""
        return list(self._quarantined_devices)
    
    def get_active_privileges(self) -> Dict[str, Dict]:
        """Get all active JIT privileges"""
        return self._active_privileges.copy()
    
    def get_enforcement_history(self, limit: int = 100) -> List[Dict]:
        """Get recent enforcement history"""
        return self._enforcement_history[-limit:]
    
    # ============================================
    # Shutdown
    # ============================================
    
    def stop(self) -> None:
        """Stop the PEP and cleanup"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._privilege_revocation_task:
            self._privilege_revocation_task.cancel()
        log.info("ZeroTrustPEP stopped")