"""
engines/device_trust_engine.py — Device Trust Engine

Assesses device identity, health, and posture for Zero Trust Layer 1.
Integrates with DeviceFingerprinter to verify device uniqueness,
monitors device health (antivirus, encryption, patches, etc.),
and maintains dynamic trust scores for every device.

Part of the Zero Trust architecture: "Never trust, always verify."
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any, Tuple
from collections import defaultdict

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity, ResponseAction,
    AgentFinding, RiskLevel
)
from utils.device_fingerprint import DeviceFingerprinter, get_device_fingerprinter

log = logging.getLogger("DeviceTrustEngine")

# ============================================
# Data Models
# ============================================

@dataclass
class DeviceHealth:
    """Device health and posture status"""
    antivirus_active: bool = False
    antivirus_updated: bool = False
    disk_encrypted: bool = False
    firewall_active: bool = False
    latest_patches: bool = False
    root_detected: bool = False
    jailbreak_detected: bool = False
    debug_mode: bool = False
    last_scan: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    issues: List[str] = field(default_factory=list)

    def is_healthy(self) -> bool:
        """Check if device meets minimum health requirements"""
        return (self.antivirus_active and self.disk_encrypted and 
                self.firewall_active and not self.root_detected and
                not self.jailbreak_detected)

@dataclass
class TrustedDeviceRecord:
    """Complete record of a trusted device"""
    device_id: str
    fingerprint_hash: str
    hardware_id: str
    mac_addresses: List[str]
    user_id: str
    device_type: str
    os_info: Dict[str, Any]
    
    # Trust metrics
    trust_score: float = 0.8
    health_score: float = 0.9
    behavior_score: float = 0.9
    overall_trust: float = 0.85
    
    # Status
    is_trusted: bool = True
    is_quarantined: bool = False
    is_active: bool = True
    
    # Timestamps
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_health_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Counters
    verification_count: int = 0
    health_check_count: int = 0
    anomaly_count: int = 0
    
    # Known IPs/networks
    known_ips: List[str] = field(default_factory=list)
    known_networks: List[str] = field(default_factory=list)
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

class DeviceTrustEngine:
    """
    Device Trust Engine - manages device trust for Zero Trust.
    
    Responsible for:
    - Device registration and fingerprinting
    - Health and posture assessment
    - Trust score calculation
    - Quarantine management
    - Continuous verification
    """
    
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._fingerprinter = get_device_fingerprinter()
        self._trusted_devices: Dict[str, TrustedDeviceRecord] = {}
        self._pending_devices: Dict[str, Dict] = {}  # Device IDs awaiting verification
        self._quarantined_devices: set = set()
        self._running = False
        
        # Configuration
        self._config = {
            "health_check_interval_seconds": 3600,  # 1 hour
            "trust_decay_days": 30,                  # Trust decays after 30 days no activity
            "min_health_requirements": {
                "antivirus": True,
                "encryption": True,
                "firewall": True,
            },
            "quarantine_on_health_fail": True,
            "auto_trust_new_devices": False,         # Require approval by default
            "max_anomalies_before_quarantine": 3,
        }
        
        # Health check state
        self._health_check_task: Optional[asyncio.Task] = None
        self._device_activity: Dict[str, datetime] = {}  # Last activity per device
        
        log.info("DeviceTrustEngine initialized")
    
    def start(self) -> None:
        """Start the engine - subscribe to events and start background tasks"""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        # Also listen for health check requests (could be custom events)
        
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        log.info("DeviceTrustEngine started")
    
    # ============================================
    # Event Handlers
    # ============================================
    
    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process threat events for device trust updates"""
        p = event.payload
        device_id = p.get("device_id") or p.get("device_info", {}).get("device_id")
        
        if not device_id:
            return
        
        # Track device activity
        self._device_activity[device_id] = datetime.now(timezone.utc)
        
        # If there's a device health event, update health
        if event.threat_type == ThreatType.DEVICE_HEALTH_FAIL:
            await self._handle_health_failure(device_id, event)
        
        # If device is quarantined due to threat, update state
        if event.threat_type == ThreatType.NETWORK_INTRUSION and event.severity == Severity.CRITICAL:
            # Could be an attack from this device - increase anomaly count
            record = self._trusted_devices.get(device_id)
            if record:
                record.anomaly_count += 1
                if record.anomaly_count >= self._config["max_anomalies_before_quarantine"]:
                    await self._quarantine_device(device_id, "Excessive anomalies")
        
        # Update known IPs/networks
        src_ip = p.get("src_ip")
        if src_ip and device_id in self._trusted_devices:
            record = self._trusted_devices[device_id]
            if src_ip not in record.known_ips:
                record.known_ips.append(src_ip)
                if len(record.known_ips) > 10:
                    record.known_ips = record.known_ips[-10:]
    
    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """React to agent findings for device trust"""
        # If an agent reported a device compromise, quarantine immediately
        if finding.metadata.get("device_id"):
            device_id = finding.metadata["device_id"]
            if finding.severity == Severity.CRITICAL and finding.confidence > 0.7:
                await self._quarantine_device(device_id, finding.summary)
        
        # Update trust scores based on agent confidence
        if finding.metadata.get("device_id"):
            device_id = finding.metadata["device_id"]
            record = self._trusted_devices.get(device_id)
            if record:
                # Adjust trust based on finding severity
                if finding.severity == Severity.HIGH:
                    record.trust_score *= 0.9
                elif finding.severity == Severity.CRITICAL:
                    record.trust_score *= 0.7
                # Recalculate overall
                self._recalculate_trust(record)
    
    # ============================================
    # Device Trust Management
    # ============================================
    
    async def register_device(self, device_info: Dict, user_id: Optional[str] = None) -> Tuple[bool, str, TrustedDeviceRecord]:
        """
        Register a new device in the trust system.
        Returns: (success, message, device_record)
        """
        # Extract device ID or generate fingerprint
        device_id = device_info.get("device_id")
        if not device_id:
            # Generate from fingerprint
            fingerprint = self._fingerprinter.get_fingerprint()
            device_id = fingerprint.device_id
        
        # Check if already registered
        if device_id in self._trusted_devices:
            return False, f"Device {device_id} already registered", self._trusted_devices[device_id]
        
        # Get fingerprint
        fingerprint = self._fingerprinter.get_fingerprint(device_id)
        
        # Create health record (simulated - in real implementation would query agent)
        health = DeviceHealth()
        # Simulate health based on provided info
        health_info = device_info.get("health", {})
        health.antivirus_active = health_info.get("antivirus_active", True)
        health.disk_encrypted = health_info.get("disk_encrypted", True)
        health.firewall_active = health_info.get("firewall_active", True)
        health.latest_patches = health_info.get("latest_patches", True)
        health.root_detected = health_info.get("root_detected", False)
        health.jailbreak_detected = health_info.get("jailbreak_detected", False)
        
        # Calculate health score
        health_score = self._calculate_health_score(health)
        
        # Determine trust level
        auto_trust = self._config["auto_trust_new_devices"]
        is_trusted = auto_trust and health.is_healthy()
        
        # Create record
        record = TrustedDeviceRecord(
            device_id=device_id,
            fingerprint_hash=fingerprint.fingerprint_hash,
            hardware_id=fingerprint.hardware_id,
            mac_addresses=fingerprint.mac_addresses,
            user_id=user_id or "unknown",
            device_type=device_info.get("device_type") or self._fingerprinter._detect_device_type(),
            os_info=device_info.get("os_info", fingerprint.os_info),
            health_score=health_score,
            is_trusted=is_trusted,
            first_seen=datetime.now(timezone.utc),
            last_verified=datetime.now(timezone.utc),
            last_health_check=datetime.now(timezone.utc),
            known_ips=device_info.get("known_ips", []),
            known_networks=device_info.get("known_networks", []),
            metadata=device_info.get("metadata", {})
        )
        
        # Recalculate overall trust
        self._recalculate_trust(record)
        
        # Store
        self._trusted_devices[device_id] = record
        
        log.info(f"Device registered: {device_id} (trusted: {is_trusted})")
        
        # If not auto-trusted, add to pending
        if not is_trusted:
            self._pending_devices[device_id] = {
                "record": record,
                "requested_at": datetime.now(timezone.utc)
            }
        
        return True, "Device registered", record
    
    async def verify_device(self, device_id: str, current_fingerprint: Optional[Dict] = None) -> Tuple[bool, float, str]:
        """
        Verify device identity and trust.
        Returns: (is_verified, confidence, reason)
        """
        if device_id not in self._trusted_devices:
            return False, 0.0, "Device not registered"
        
        record = self._trusted_devices[device_id]
        
        # Check if quarantined
        if record.is_quarantined or device_id in self._quarantined_devices:
            return False, 0.0, "Device quarantined"
        
        # If not trusted, fail
        if not record.is_trusted:
            return False, 0.3, "Device not trusted"
        
        # Get current fingerprint
        fingerprint = self._fingerprinter.get_fingerprint(device_id)
        
        # Verify fingerprint
        stored_fingerprint = self._fingerprinter.get_fingerprint(device_id)
        # Actually we need to compare fingerprint with stored
        # But we have the record's fingerprint_hash, so we can compare
        if record.fingerprint_hash != fingerprint.fingerprint_hash:
            # Could be cloned device - treat as high risk
            record.anomaly_count += 1
            if record.anomaly_count >= self._config["max_anomalies_before_quarantine"]:
                await self._quarantine_device(device_id, "Fingerprint mismatch")
            return False, 0.2, "Fingerprint mismatch - possible clone"
        
        # Verify hardware ID and MACs
        if record.hardware_id != fingerprint.hardware_id:
            record.anomaly_count += 1
            return False, 0.3, "Hardware ID mismatch"
        
        # At least one MAC should match
        if record.mac_addresses and fingerprint.mac_addresses:
            if not set(record.mac_addresses) & set(fingerprint.mac_addresses):
                record.anomaly_count += 1
                return False, 0.25, "No matching MAC address"
        
        # Update verification
        record.last_verified = datetime.now(timezone.utc)
        record.verification_count += 1
        self._device_activity[device_id] = datetime.now(timezone.utc)
        
        return True, record.overall_trust, "Device verified"
    
    async def update_device_health(self, device_id: str, health_info: Dict) -> bool:
        """Update health status for a device"""
        if device_id not in self._trusted_devices:
            return False
        
        record = self._trusted_devices[device_id]
        health = DeviceHealth(
            antivirus_active=health_info.get("antivirus_active", record.health_score > 0.5),
            disk_encrypted=health_info.get("disk_encrypted", True),
            firewall_active=health_info.get("firewall_active", True),
            latest_patches=health_info.get("latest_patches", True),
            root_detected=health_info.get("root_detected", False),
            jailbreak_detected=health_info.get("jailbreak_detected", False),
            last_scan=datetime.now(timezone.utc),
            issues=health_info.get("issues", [])
        )
        
        # Update health score
        record.health_score = self._calculate_health_score(health)
        record.last_health_check = datetime.now(timezone.utc)
        record.health_check_count += 1
        
        # Recalculate overall trust
        self._recalculate_trust(record)
        
        # If health fails and quarantine is enabled
        if not health.is_healthy() and self._config["quarantine_on_health_fail"]:
            # If health score drops below threshold, quarantine
            if record.health_score < 0.4:
                await self._quarantine_device(device_id, "Health score below threshold")
        
        log.info(f"Device health updated for {device_id}: {record.health_score:.2f}")
        return True
    
    async def _quarantine_device(self, device_id: str, reason: str) -> None:
        """Quarantine a compromised device"""
        if device_id in self._quarantined_devices:
            return
        
        self._quarantined_devices.add(device_id)
        
        # Update record
        if device_id in self._trusted_devices:
            record = self._trusted_devices[device_id]
            record.is_quarantined = True
            record.is_trusted = False
            record.trust_score = 0.0
        
        log.warning(f"Device quarantined: {device_id} - {reason}")
        
        # Publish quarantine event
        quarantine_event = ThreatEvent(
            source="DeviceTrustEngine",
            threat_type=ThreatType.DEVICE_HEALTH_FAIL,
            severity=Severity.CRITICAL,
            payload={
                "device_id": device_id,
                "reason": reason,
                "action": "quarantine"
            }
        )
        await self.bus.publish(quarantine_event)
    
    async def unquarantine_device(self, device_id: str) -> bool:
        """Remove device from quarantine (if resolved)"""
        if device_id not in self._quarantined_devices:
            return False
        
        self._quarantined_devices.remove(device_id)
        
        if device_id in self._trusted_devices:
            record = self._trusted_devices[device_id]
            record.is_quarantined = False
            record.is_trusted = True
            # Reset trust score gradually (not full restore)
            record.trust_score = 0.5
            record.anomaly_count = 0
            self._recalculate_trust(record)
        
        log.info(f"Device unquarantined: {device_id}")
        return True
    
    def _recalculate_trust(self, record: TrustedDeviceRecord) -> None:
        """Recalculate overall trust score from sub-scores"""
        # Weighted average: 40% health, 30% fingerprint confidence, 20% behavior (from anomalies), 10% age
        health_weight = 0.4
        fingerprint_weight = 0.3
        behavior_weight = 0.2
        age_weight = 0.1
        
        # Health score
        health = record.health_score
        
        # Fingerprint confidence (from device fingerprint)
        fp_conf = self._fingerprinter.get_fingerprint(record.device_id).confidence
        
        # Behavior score: start at 1.0, reduce with anomalies
        behavior = max(0.0, 1.0 - (record.anomaly_count * 0.1))
        
        # Age factor: newer devices get slightly lower trust until proven
        age_days = (datetime.now(timezone.utc) - record.first_seen).days
        age_factor = min(1.0, 0.7 + (age_days / 30))  # Ramp up over 30 days
        
        # Compute
        overall = (health * health_weight + 
                   fp_conf * fingerprint_weight + 
                   behavior * behavior_weight + 
                   age_factor * age_weight)
        
        # Ensure within 0-1
        overall = max(0.0, min(1.0, overall))
        record.overall_trust = overall
        
        # Update trust_score to overall
        record.trust_score = overall
        
        # If overall below threshold, mark not trusted
        if overall < 0.4:
            record.is_trusted = False
        else:
            record.is_trusted = True
    
    def _calculate_health_score(self, health: DeviceHealth) -> float:
        """Calculate health score from health object"""
        score = 0.0
        checks = [
            health.antivirus_active,
            health.disk_encrypted,
            health.firewall_active,
            health.latest_patches,
            not health.root_detected,
            not health.jailbreak_detected,
            not health.debug_mode,
        ]
        score = sum(1 for c in checks if c) / len(checks)
        return min(1.0, max(0.0, score))
    
    # ============================================
    # Background Health Checks
    # ============================================
    
    async def _health_check_loop(self) -> None:
        """Periodically check device health"""
        while self._running:
            await asyncio.sleep(self._config["health_check_interval_seconds"])
            try:
                now = datetime.now(timezone.utc)
                for device_id, record in list(self._trusted_devices.items()):
                    # Check if device has been inactive for too long -> trust decay
                    last_activity = self._device_activity.get(device_id)
                    if last_activity:
                        days_inactive = (now - last_activity).days
                        if days_inactive > self._config["trust_decay_days"]:
                            # Decay trust
                            decay = min(0.3, days_inactive / 100)
                            record.trust_score = max(0.0, record.trust_score - decay)
                            self._recalculate_trust(record)
                            log.debug(f"Trust decay for {device_id}: {decay:.2f}")
                    
                    # Periodically verify fingerprint (simulate)
                    if record.verification_count % 10 == 0:
                        # Re-verify fingerprint
                        try:
                            fingerprint = self._fingerprinter.get_fingerprint(device_id)
                            if record.fingerprint_hash != fingerprint.fingerprint_hash:
                                await self._quarantine_device(device_id, "Fingerprint mismatch during periodic check")
                        except Exception as e:
                            log.error(f"Fingerprint re-verification failed for {device_id}: {e}")
            except Exception as e:
                log.error(f"Health check loop error: {e}")
    
    # ============================================
    # Public Query Methods
    # ============================================
    
    def get_device_trust(self, device_id: str) -> Optional[float]:
        """Get overall trust score for a device"""
        record = self._trusted_devices.get(device_id)
        return record.overall_trust if record else None
    
    def get_device_record(self, device_id: str) -> Optional[TrustedDeviceRecord]:
        """Get full device record"""
        return self._trusted_devices.get(device_id)
    
    def is_device_trusted(self, device_id: str) -> bool:
        """Check if device is trusted"""
        record = self._trusted_devices.get(device_id)
        return record is not None and record.is_trusted and not record.is_quarantined
    
    def is_device_quarantined(self, device_id: str) -> bool:
        """Check if device is quarantined"""
        return device_id in self._quarantined_devices
    
    def list_trusted_devices(self) -> List[TrustedDeviceRecord]:
        """List all trusted devices"""
        return [r for r in self._trusted_devices.values() if r.is_trusted and not r.is_quarantined]
    
    def list_quarantined_devices(self) -> List[str]:
        """List quarantined device IDs"""
        return list(self._quarantined_devices)
    
    def list_pending_devices(self) -> List[Dict]:
        """List devices awaiting trust approval"""
        return [
            {
                "device_id": device_id,
                "record": data["record"],
                "requested_at": data["requested_at"]
            }
            for device_id, data in self._pending_devices.items()
        ]
    
    def approve_device(self, device_id: str) -> bool:
        """Approve a pending device"""
        if device_id not in self._pending_devices:
            return False
        
        record = self._trusted_devices[device_id]
        record.is_trusted = True
        self._recalculate_trust(record)
        del self._pending_devices[device_id]
        
        log.info(f"Device approved: {device_id}")
        return True
    
    def reject_device(self, device_id: str) -> bool:
        """Reject a pending device (remove from system)"""
        if device_id in self._trusted_devices:
            del self._trusted_devices[device_id]
        if device_id in self._pending_devices:
            del self._pending_devices[device_id]
        log.info(f"Device rejected and removed: {device_id}")
        return True
    
    # ============================================
    # Event Handlers for Health Failures
    # ============================================
    
    async def _handle_health_failure(self, device_id: str, event: ThreatEvent) -> None:
        """Handle device health failure events"""
        record = self._trusted_devices.get(device_id)
        if not record:
            return
        
        # Extract health issues from event
        p = event.payload
        issue = p.get("issue", "Unknown health issue")
        record.health_score = max(0.0, record.health_score - 0.1)
        self._recalculate_trust(record)
        
        log.warning(f"Health failure for {device_id}: {issue}, new score: {record.health_score:.2f}")
    
    # ============================================
    # Shutdown
    # ============================================
    
    def stop(self) -> None:
        """Stop the engine"""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
        log.info("DeviceTrustEngine stopped")