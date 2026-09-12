"""
events.py — Shared data models for AiBoO.
Extended with tri-gate architecture: GateLevel, GateVerdict, GateDecision,
Zero Trust types: AccessRequest, ZeroTrustDecision, RiskLevel,
Layer 2 Detection & Intelligence types,
and Layer 3 Cyber‑Physical Convergence types.
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ThreatType(str, Enum):
    # ---- Existing threat types ----
    NETWORK_INTRUSION = "network_intrusion"
    IDENTITY_MISMATCH = "identity_mismatch"
    PHYSICAL_INTRUSION = "physical_intrusion"
    INSIDER_THREAT = "insider_threat"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    CORRELATED_ATTACK = "correlated_attack"
    MEMORY_THREAT = "memory_threat"

    # ---- Zero Trust additions ----
    ACCESS_REQUEST = "access_request"
    DEVICE_HEALTH_FAIL = "device_health_fail"
    ZERO_TRUST_VIOLATION = "zero_trust_violation"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    GEO_VELOCITY = "geo_velocity"

    # ---- Layer 2 Detection & Intelligence additions ----
    THREAT_INTEL_ALERT = "threat_intel_alert"           # IOC matches, dark web mentions
    PHYSICAL_CYBER_MISMATCH = "physical_cyber_mismatch"  # Ghost logins, zone mismatches

    # ---- Layer 3 Cyber‑Physical Convergence additions ----
    GHOST_LOGIN = "ghost_login"                         # Login from impossible location
    INSIDER_THREAT_CONVERGED = "insider_threat_converged" # Multi‑day insider pattern
    TAILGATING = "tailgating"                           # Badge mismatch + CCTV
    RANSOMWARE_PRELUDE = "ransomware_prelude"           # Pre‑attack sequence

    # ---- Windows Security Log event types (plugin) ----
    FAILED_LOGON = "failed_logon"
    LOGON_SUCCESS = "logon_success"
    PRIVILEGE_USE = "privilege_use"
    EXPLICIT_CRED = "explicit_cred"
    PROCESS_CREATE = "process_create"
    CONN_ALLOW = "conn_allow"
    CONN_BLOCK = "conn_block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class ResponseAction(str, Enum):
    # Existing actions
    LOG = "log"
    ALERT_DASHBOARD = "alert_dashboard"
    ISOLATE_ASSET = "isolate_asset"
    PSEUDO_LOCK = "pseudo_lock"
    REVOKE_IDENTITY = "revoke_identity"
    NOTIFY_SECURITY = "notify_security"
    ESCALATE_SOC = "escalate_soc"
    LOCK_ZONE = "lock_zone"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"

    # ---- Zero Trust actions ----
    ALLOW_ACCESS = "allow_access"
    BLOCK_ACCESS = "block_access"
    CHALLENGE_MFA = "challenge_mfa"
    REVOKE_SESSION = "revoke_session"
    QUARANTINE_DEVICE = "quarantine_device"
    FORCE_LOGOUT = "force_logout"
    STEP_UP_AUTH = "step_up_auth"
    GRANT_TEMP_PRIVILEGE = "grant_temp_privilege"
    SCHEDULE_PRIVILEGE_REVOCATION = "schedule_privilege_revocation"

    # ---- Layer 3 Cyber‑Physical Convergence actions ----
    NOTIFY_HR = "notify_hr"          # Alert Human Resources
    NOTIFY_LEGAL = "notify_legal"    # Alert Legal department


# ---- Zero Trust risk levels ----
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Tri-gate types ────────────────────────────────────────────────────────────

class GateLevel(int, Enum):
    GATE_1 = 1   # Perimeter intelligence
    GATE_2 = 2   # Behavioural intelligence
    GATE_3 = 3   # Adaptive response

    def label(self) -> str:
        return {1: "Perimeter", 2: "Behavioural", 3: "Adaptive Response"}[self.value]


class GateVerdict(str, Enum):
    PASS = "pass"          # Below threshold — allow through
    HOLD = "hold"          # Suspicious — pass to next gate
    BLOCK = "block"        # Confirmed — stop and respond
    ESCALATE = "escalate"  # Critical — skip to Gate 3 immediately


@dataclass
class GateDecision:
    gate: GateLevel
    event_id: str
    threat_type: ThreatType
    severity: Severity
    verdict: GateVerdict
    confidence: float
    reason: str
    actions: list[ResponseAction]
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Original models ───────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    source: str
    threat_type: ThreatType
    severity: Severity
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AgentFinding:
    agent_name: str
    event_id: str
    threat_type: ThreatType
    severity: Severity
    confidence: float
    summary: str
    actions: list[ResponseAction]
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CorrelatedAlert:
    alert_id: str
    threat_type: ThreatType
    severity: Severity
    confidence: float
    description: str
    findings: list[AgentFinding]
    actions: list[ResponseAction]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PseudoLockRestoreRequest:
    """Published when the dashboard requests a pseudo-lock to be restored."""
    lock_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Zero Trust models ─────────────────────────────────────────────────────────

@dataclass
class AccessRequest:
    """
    Represents a request for access to a resource.
    Used by the Zero Trust PDP to evaluate policy.
    """
    user_id: str
    device_id: str
    resource: str
    timestamp: datetime
    location: str = ""
    network: str = ""
    behavior_context: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    session_id: str = ""
    source: str = ""


@dataclass
class ZeroTrustDecision:
    """
    Final decision from the Zero Trust PDP.
    Contains allowance, risk level, and required enforcement actions.
    """
    request_id: str
    allowed: bool
    risk_level: RiskLevel
    required_actions: list[ResponseAction]
    reason: str
    confidence: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))