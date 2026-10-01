"""
events.py — Shared data models for AiBoO.
Extended with tri-gate architecture: GateLevel, GateVerdict, GateDecision,
Zero Trust types: AccessRequest, ZeroTrustDecision, RiskLevel,
Layer 2 Detection & Intelligence types,
Layer 3 Cyber‑Physical Convergence types,
and Response Action tracking (ActionRecord, ActionStatus).
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


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

    # ---- Dynamic access control (response/access_control.py) ----
    RESTRICT_IDENTITY = "restrict_identity"    # disable account for N min + log off, auto re-enable
    LIFT_RESTRICTION = "lift_restriction"      # re-enable now
    THROTTLE_SEGMENT = "throttle_segment"      # Windows QoS bandwidth limit to an IP / range
    REMOVE_THROTTLE = "remove_throttle"

    # ---- Layer 3 Cyber‑Physical Convergence actions ----
    NOTIFY_HR = "notify_hr"          # Alert Human Resources
    NOTIFY_LEGAL = "notify_legal"    # Alert Legal department


# ---- Zero Trust risk levels ----
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---- NEW: Action lifecycle status (for the Isolation & Termination tab) ----
class ActionStatus(str, Enum):
    """
    Lifecycle status of a response action.

    PENDING  — Dispatched to the engine, not yet completed
    SUCCESS  — Completed successfully
    FAILED   — Could not be completed (see ActionRecord.error)
    ACTIVE   — Ongoing containment (e.g. pseudo-lock, JIT grant)
    """
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    ACTIVE = "active"


# ── Tri-gate types ────────────────────────────────────────────────────────────

class GateLevel(int, Enum):
    GATE_1 = 1   # Trust  - who is it, can we trust them?
    GATE_2 = 2   # Intent - is it an attack?
    GATE_3 = 3   # Impact - how bad would it be? (+ final TriGate decision)

    def label(self) -> str:
        return {1: "Trust", 2: "Intent", 3: "Impact"}[self.value]


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


@dataclass
class PseudoLockUpdate:
    """
    Published by PseudoLockAgent whenever a decoy listener is really opened
    (active=True) or really closed (active=False). The dashboard bridge
    forwards it, so the Locks tab only shows locks that exist on the PC.
    """
    lock_id: str
    active: bool
    event_id: str = ""
    agent: str = "PseudoLockAgent"
    severity: str = "high"
    summary: str = ""
    decoy_port: int | None = None
    decoy_endpoint: str = ""
    original_endpoint: str = ""
    hits: int = 0
    message: str = ""
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


# ── NEW: Response Action tracking ─────────────────────────────────────────────

@dataclass
class ActionRecord:
    """
    One row in the "Isolation & Termination" tab.

    Emitted by `RealResponseEngine` for *every* response action it
    executes — including isolate, terminate, quarantine, pseudo-lock,
    revoke identity, lock zone, force logout, and quarantine file.

    Flow:
        RealResponseEngine.execute()
            → publishes ActionRecord on EventBus
            → DashboardBridge._on_action() forwards to POST /api/agent/actions
            → backend stores + emits `agent:action` via Socket.IO
            → frontend AgentConsole renders it live

    Lifecycle:
        A PENDING record is published *before* the handler runs, then the
        same record is republished with its final status (SUCCESS / FAILED /
        ACTIVE). The frontend dedupes by `action_id`, so only one row shows.
    """

    action_id: str
    action: str                                   # e.g. "terminate_process"
    target: str                                   # "powershell.exe (PID: 1234)"
    target_type: str = "unknown"                  # process | ip | device | identity | file | zone
    status: str = ActionStatus.PENDING.value      # pending | success | failed | active
    details: str = ""
    reason: str = ""
    agent_name: str = ""
    severity: str = Severity.MEDIUM.value
    triggered_by: str = ""                        # originating finding / alert id
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = True
    error: Optional[str] = None
    dry_run: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------
    @classmethod
    def from_action(
        cls,
        action: "ResponseAction | str",
        target: str,
        *,
        target_type: str = "unknown",
        agent_name: str = "",
        severity: "Severity | str" = Severity.MEDIUM,
        triggered_by: str = "",
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> "ActionRecord":
        """Build a PENDING record ready to be published on the bus."""
        action_value = (
            action.value if isinstance(action, ResponseAction) else str(action)
        )
        severity_value = (
            severity.value if isinstance(severity, Severity) else str(severity)
        )
        return cls(
            action_id=f"act_{uuid.uuid4().hex[:12]}",
            action=action_value,
            target=target,
            target_type=target_type,
            agent_name=agent_name,
            severity=severity_value,
            triggered_by=triggered_by,
            reason=reason,
            metadata=dict(metadata or {}),
        )

    # ------------------------------------------------------------------
    # Status transition helpers
    # ------------------------------------------------------------------
    def mark_success(self, details: str = "", **metadata: Any) -> "ActionRecord":
        """Mark the record as successfully completed."""
        self.status = ActionStatus.SUCCESS.value
        self.success = True
        self.error = None
        if details:
            self.details = details
        if metadata:
            self.metadata.update(metadata)
        return self

    def mark_active(self, details: str = "", **metadata: Any) -> "ActionRecord":
        """Mark the record as actively containing (pseudo-lock, JIT grant)."""
        self.status = ActionStatus.ACTIVE.value
        self.success = True
        self.error = None
        if details:
            self.details = details
        if metadata:
            self.metadata.update(metadata)
        return self

    def mark_failed(
        self, error: str, details: str = ""
    ) -> "ActionRecord":
        """Mark the record as failed — sets .error for the frontend."""
        self.status = ActionStatus.FAILED.value
        self.success = False
        self.error = error
        if details:
            self.details = details
        return self