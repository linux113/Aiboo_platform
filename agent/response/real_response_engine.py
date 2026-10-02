from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union

import psutil

from core.event_bus import EventBus
from core.events import (
    ActionRecord,
    ActionStatus,
    AgentFinding,
    GateDecision,
    GateLevel,
    GateVerdict,
    ResponseAction,
    RiskLevel,
    Severity,
    ThreatType,
)

log = logging.getLogger("RealResponseEngine")

_USER_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_.@\\-]+$')


def _validate_user_id(user_id: str) -> bool:
    return bool(_USER_ID_PATTERN.match(user_id))


# Prefixes that mean "an account on this very PC". Windows event logs give
# names like "MYPC\\alice", but `net user` only accepts the bare "alice".
_LOCAL_DOMAIN_ALIASES = {".", "builtin", "localhost"}


def _local_computer_names() -> set:
    import socket
    names = set(_LOCAL_DOMAIN_ALIASES)
    for n in (os.environ.get("COMPUTERNAME"), socket.gethostname()):
        if n:
            names.add(n.lower())
            names.add(n.split(".")[0].lower())
    return names


def _to_local_account_name(user_id: str) -> str:
    """'MYPC\\alice' -> 'alice' when MYPC is this computer.

    A real domain account (e.g. 'CORP\\alice') can't be disabled with a plain
    `net user` on this PC, so we refuse with a clear message instead of letting
    Windows print its confusing "syntax of this command" help text.
    """
    if "\\" not in user_id:
        return user_id
    domain, name = user_id.rsplit("\\", 1)
    if not name:
        raise RuntimeError(f"Invalid user_id format: {user_id}")
    if domain.lower() in _local_computer_names():
        return name
    raise RuntimeError(
        f"'{user_id}' is a domain account (domain '{domain}'). It can only be "
        f"disabled on the domain controller, not on this PC.")


_SYSTEM_ACCOUNTS = {"system", "local service", "network service", "localsystem"}


def _refuse_if_self_or_system(name: str) -> None:
    """Never let a Run click lock the person out of their own PC."""
    low = name.lower()
    if low in _SYSTEM_ACCOUNTS:
        raise RuntimeError(f"Refusing to disable '{name}': it is a built-in Windows system account.")
    me = set()
    for getter in (lambda: os.environ.get("USERNAME", ""),
                   lambda: __import__("getpass").getuser()):
        try:
            v = getter()
        except Exception:
            v = ""
        if v:
            me.add(v.split("\\")[-1].lower())
    if low in me:
        raise RuntimeError(
            f"Refusing to disable '{name}': it is the account this agent is running as "
            f"(you would lock yourself out). Disable it from another admin account if needed.")


# ---------------------------------------------------------------------------
# Never-kill list - processes whose termination would BSOD, break the OS,
# or kill our own agent. Checked by name (case-insensitive) before any kill.
# ---------------------------------------------------------------------------
_PROTECTED_PROCESS_NAMES = {
    # ---- Windows critical ----
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
    # svchost is protected because killing it usually BSODs; malicious
    # code injected into svchost should be handled by an operator, not
    # by an automated kill.
    "svchost.exe",
    # ---- Linux critical ----
    "systemd", "init", "kthreadd", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog",
    # ---- Our own agent ----
    "python.exe", "python3", "pythonw.exe", "python",
}

# ---------------------------------------------------------------------------
# Only these threat types warrant automated termination. Everything else
# gets logged as an alert and left for a human.
# ---------------------------------------------------------------------------
_AUTO_TERMINATE_THREATS = {
    "ransomware_prelude",
    "network_intrusion",
    "insider_threat",
    "insider_threat_converged",
    "memory_threat",
    "correlated_attack",
    "process_create",
}

# ---------------------------------------------------------------------------
# Final status + target type for each action, used by the Isolation &
# Termination tab in the dashboard.
# ---------------------------------------------------------------------------
_ACTION_META: Dict[ResponseAction, tuple] = {
    ResponseAction.TERMINATE_PROCESS:               ("process",  ActionStatus.SUCCESS),
    ResponseAction.ISOLATE_ASSET:                   ("ip",       ActionStatus.SUCCESS),
    ResponseAction.BLOCK_ACCESS:                    ("ip",       ActionStatus.SUCCESS),
    ResponseAction.ALLOW_ACCESS:                    ("ip",       ActionStatus.SUCCESS),
    ResponseAction.QUARANTINE_DEVICE:               ("device",   ActionStatus.SUCCESS),
    ResponseAction.PSEUDO_LOCK:                     ("identity", ActionStatus.ACTIVE),
    ResponseAction.REVOKE_IDENTITY:                 ("identity", ActionStatus.SUCCESS),
    ResponseAction.FORCE_LOGOUT:                    ("identity", ActionStatus.SUCCESS),
    ResponseAction.REVOKE_SESSION:                  ("identity", ActionStatus.SUCCESS),
    ResponseAction.CHALLENGE_MFA:                   ("identity", ActionStatus.SUCCESS),
    ResponseAction.STEP_UP_AUTH:                    ("identity", ActionStatus.SUCCESS),
    ResponseAction.GRANT_TEMP_PRIVILEGE:            ("identity", ActionStatus.ACTIVE),
    ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION:   ("identity", ActionStatus.SUCCESS),
    ResponseAction.NOTIFY_SECURITY:                 ("unknown",  ActionStatus.SUCCESS),
    ResponseAction.RESTRICT_IDENTITY:               ("identity", ActionStatus.ACTIVE),
    ResponseAction.LIFT_RESTRICTION:                ("identity", ActionStatus.SUCCESS),
    ResponseAction.THROTTLE_SEGMENT:                ("ip",       ActionStatus.ACTIVE),
    ResponseAction.REMOVE_THROTTLE:                 ("ip",       ActionStatus.SUCCESS),
}

Event = Union[GateDecision, AgentFinding]


class RealResponseEngine:
    """
    Executes response actions and publishes an ActionRecord for each one.

    Auto-termination:
        When a high-severity finding arrives that includes a pid and matches
        the policy (_AUTO_TERMINATE_THREATS, confidence gate, protect list),
        the engine terminates the process immediately and publishes the
        resulting ActionRecord so the Isolation & Termination tab shows it.

        Configure via environment variables:
            AIBOO_AUTO_TERMINATE=0|1          (default: 1 - enabled)
            AIBOO_AUTO_TERMINATE_SEVERITIES   (default: "high,critical")
            AIBOO_AUTO_TERMINATE_MIN_CONF     (default: "0.8")
            AIBOO_DRY_RUN=1                   (skip actual kills, log only)

    Remote execution:
        execute_remote_action() is the entry point for commands pushed by the
        backend over the CommandChannel WebSocket. It wraps the incoming
        command in a synthetic AgentFinding so the normal _execute_action
        pipeline runs unchanged - ActionRecords get published, DashboardBridge
        forwards them, the dashboard shows the row.
    """

    def __init__(self, bus: EventBus, auto_response: bool = True):
        self.bus = bus
        self._active_jit_grants: Dict[str, Dict[str, Any]] = {}
        # Set by the orchestrator to the PseudoLockAgent, so a pseudo_lock
        # action opens a REAL decoy listener (and Restore can close it).
        self.pseudo_lock_provider = None

        # ---- Auto-termination policy ----
        # auto_response=False -> engine only runs explicit remote commands.
        self._auto_terminate_enabled = auto_response and os.getenv(
            "AIBOO_AUTO_TERMINATE", "1"
        ).lower() in ("1", "true", "yes", "on")

        self._auto_terminate_severities = {
            s.strip().lower()
            for s in os.getenv(
                "AIBOO_AUTO_TERMINATE_SEVERITIES", "high,critical"
            ).split(",")
            if s.strip()
        }

        try:
            self._auto_terminate_min_confidence = float(
                os.getenv("AIBOO_AUTO_TERMINATE_MIN_CONF", "0.8")
            )
        except ValueError:
            self._auto_terminate_min_confidence = 0.8

        self._dry_run = os.getenv("AIBOO_DRY_RUN", "").lower() in (
            "1", "true", "yes", "on"
        )

        # Cache of our own pid + parent so we never kill ourselves
        self._self_pid = os.getpid()
        try:
            self._parent_pid = psutil.Process(self._self_pid).ppid()
        except Exception:
            self._parent_pid = None

        if self._auto_terminate_enabled:
            log.warning(
                "AUTO-TERMINATE ENABLED - severities=%s, min_confidence=%.2f, "
                "dry_run=%s",
                sorted(self._auto_terminate_severities),
                self._auto_terminate_min_confidence,
                self._dry_run,
            )
        else:
            log.info("Auto-terminate disabled")

    def start(self):
        self.bus.subscribe(GateDecision, self._on_decision)
        self.bus.subscribe(AgentFinding, self._on_finding)
        log.info("Real Response Engine - ACTIVE (Zero Trust + auto-response)")

    # ============================================================
    # Event handlers
    # ============================================================

    async def _on_decision(self, decision: GateDecision):
        """Gate 3 BLOCK -> run every action in the decision."""
        if decision.gate != GateLevel.GATE_3 or decision.verdict != GateVerdict.BLOCK:
            return
        for action in decision.actions:
            await self._execute_action(action, decision)

    async def _on_finding(self, finding: AgentFinding):
        """
        Auto-terminate on high-severity findings that carry a pid.

        Policy gates (ALL must pass):
            1. Auto-terminate enabled
            2. Severity in _auto_terminate_severities
            3. Threat type in _AUTO_TERMINATE_THREATS
            4. Confidence >= _auto_terminate_min_confidence
            5. A pid is present
            6. Process is not on the protect list / not us / not our parent
        """
        if not self._auto_terminate_enabled:
            return

        severity = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        ).lower()

        if severity not in self._auto_terminate_severities:
            return

        threat = (
            finding.threat_type.value
            if hasattr(finding.threat_type, "value")
            else str(finding.threat_type)
        ).lower()

        if threat not in _AUTO_TERMINATE_THREATS:
            log.debug(
                "Auto-terminate skipped: threat_type=%s not in policy", threat
            )
            return

        if finding.confidence < self._auto_terminate_min_confidence:
            log.info(
                "Auto-terminate skipped: confidence %.2f < %.2f for %s",
                finding.confidence,
                self._auto_terminate_min_confidence,
                finding.event_id,
            )
            return

        pid = self._extract_pid(finding)
        if not pid:
            log.info(
                "Auto-terminate skipped: no pid in finding %s", finding.event_id
            )
            return

        # Protect-list check happens inside _terminate_process, but do a
        # quick pre-check so we log the reason clearly.
        allowed, reason = self._is_kill_allowed(pid)
        if not allowed:
            log.warning(
                "Auto-terminate REFUSED for pid %s: %s (event %s)",
                pid, reason, finding.event_id,
            )
            return

        log.warning(
            "AUTO-TERMINATE -> pid=%s threat=%s severity=%s confidence=%.2f",
            pid, threat, severity, finding.confidence,
        )

        # Route through the normal action pipeline so an ActionRecord is
        # published and the dashboard tab picks it up.
        await self._execute_action(ResponseAction.TERMINATE_PROCESS, finding)

    # ============================================================
    # Remote command entry point (from CommandChannel)
    # ============================================================

    async def execute_remote_action(
        self,
        action_name: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Entry point for commands pushed via the CommandChannel WebSocket.

        Wraps the incoming action in a synthetic AgentFinding so the normal
        _execute_action pipeline runs unchanged - ActionRecords get published,
        DashboardBridge forwards them, the dashboard shows the row.

        Called by CommandChannel._handle_command() when the backend
        dispatches a remote action to this endpoint.

        Args:
            action_name: ResponseAction value string, e.g. "terminate_process"
            target:      target identifier (pid / ip / user_id / device_id)
            params:      optional dict - pid, src_ip, user_id, device_id,
                         process_name, severity, confidence, etc.

        Returns:
            {"message": <what was done>, "status": <record status>} - sent back
            to the dashboard in the "executed" ack, so approvals and playbook
            runs show e.g. "Account 'x' disabled for 30 min" instead of "Done".
        """
        params = dict(params or {})
        target = str(target or "").strip()

        try:
            action = ResponseAction(action_name)
        except ValueError:
            log.error("Unknown remote action: %s", action_name)
            raise RuntimeError(f"Unknown action: {action_name}")

        log.warning(
            "REMOTE ACTION -> %s (target=%s)", action.value, target or "-",
        )

        # ---- Resolve / validate the target for the chosen action ----
        # The dashboard sends a single free-text "target". Map it to the
        # field the handler actually needs (pid, src_ip, user_id, ...).
        if action == ResponseAction.TERMINATE_PROCESS:
            pids = self._resolve_remote_pids(target, params)
            if len(pids) > 1:
                # A process name matched several instances: kill each one
                # (each gets its own ActionRecord row on the dashboard).
                errors = []
                for pid in pids:
                    sub = {**params, "pid": pid}
                    try:
                        await self.execute_remote_action(action.value, str(pid), sub)
                    except Exception as exc:
                        errors.append(f"{pid}: {exc}")
                if errors:
                    raise RuntimeError(
                        f"{len(errors)}/{len(pids)} kills failed - " + "; ".join(errors)
                    )
                return {"message": f"Stopped {len(pids)} processes matching '{target}'", "status": "success"}
            params["pid"] = pids[0]
            if not params.get("process_name"):
                try:
                    params["process_name"] = psutil.Process(pids[0]).name()
                except Exception:
                    pass  # process gone / access denied - handler reports it
        elif action in (ResponseAction.ISOLATE_ASSET,
                        ResponseAction.BLOCK_ACCESS,
                        ResponseAction.ALLOW_ACCESS):
            params["src_ip"] = self._validate_remote_ip(params.get("src_ip") or target)
        elif action in (ResponseAction.THROTTLE_SEGMENT, ResponseAction.REMOVE_THROTTLE):
            segment = str(params.get("segment") or target).strip()
            try:
                params["segment"] = str(ipaddress.ip_network(segment, strict=False))
            except ValueError:
                raise RuntimeError(f"{action.value} needs an IP address or range, e.g. 203.0.113.7 "
                                   f"or 192.168.1.0/24 (got {segment!r})")
        elif action in (ResponseAction.REVOKE_IDENTITY,
                        ResponseAction.RESTRICT_IDENTITY,
                        ResponseAction.LIFT_RESTRICTION,
                        ResponseAction.FORCE_LOGOUT,
                        ResponseAction.REVOKE_SESSION,
                        ResponseAction.CHALLENGE_MFA,
                        ResponseAction.STEP_UP_AUTH,
                        ResponseAction.GRANT_TEMP_PRIVILEGE,
                        ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION):
            user_id = str(params.get("user_id") or target).strip()
            if not user_id:
                raise RuntimeError(f"{action.value} needs a user ID as target")
            if not _validate_user_id(user_id):
                raise RuntimeError(f"Invalid user_id format: {user_id}")
            if action in (ResponseAction.REVOKE_IDENTITY, ResponseAction.RESTRICT_IDENTITY,
                          ResponseAction.FORCE_LOGOUT, ResponseAction.REVOKE_SESSION) \
                    and self._is_current_user(user_id):
                raise RuntimeError(
                    f"Refusing to disable '{user_id}': it is the account the agent "
                    f"is running as (you would lock yourself out)"
                )
            params["user_id"] = user_id
        elif action == ResponseAction.QUARANTINE_DEVICE:
            if not (params.get("device_id") or target):
                raise RuntimeError("quarantine_device needs a device ID as target")

        # Build a payload that the existing _extract_* helpers understand.
        # The helpers look for pid / src_ip / user_id / device_id in
        # metadata.payload, metadata.payload.raw_payload, or metadata directly.
        payload: Dict[str, Any] = {
            "target": target,
            "src_ip": params.get("src_ip"),
            "pid": params.get("pid"),
            "user_id": params.get("user_id") or (target if action == ResponseAction.PSEUDO_LOCK else None),
            "device_id": params.get("device_id") or (target if action == ResponseAction.QUARANTINE_DEVICE else None),
            "process_name": params.get("process_name"),
            "jit_duration_minutes": params.get("jit_duration_minutes"),
            "segment": params.get("segment"),
            "minutes": params.get("minutes"),
            "kbps": params.get("kbps"),
        }

        # Only keep keys with real values so _pick() falls through cleanly
        payload = {k: v for k, v in payload.items() if v not in (None, "")}

        severity_value = str(params.get("severity", "high")).lower()
        try:
            severity = Severity(severity_value)
        except ValueError:
            severity = Severity.HIGH

        try:
            confidence = float(params.get("confidence", 1.0))
        except (TypeError, ValueError):
            confidence = 1.0

        synthetic = AgentFinding(
            agent_name="RemoteCommand",
            event_id=f"remote_{uuid.uuid4().hex[:8]}",
            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
            severity=severity,
            confidence=confidence,
            summary=f"Remote command from dashboard: {action.value} -> {target}",
            actions=[action],
            metadata={
                "payload": payload,
                "remote": True,
                "target": target,
                **{k: v for k, v in params.items() if k not in payload},
            },
        )

        record = await self._execute_action(action, synthetic)
        if record is None:
            raise RuntimeError(f"No handler for action: {action.value}")
        if record.status == ActionStatus.FAILED.value:
            # Surface the failure to the CommandChannel so the dashboard
            # gets a "failed" ack with the real reason.
            raise RuntimeError(record.error or f"{action.value} failed")
        message = str(record.details or "").strip() or f"{action.value} done on {record.target or target or 'this PC'}"
        return {"message": message[:500], "status": record.status}

    # ---- Remote target helpers ----

    def _resolve_remote_pids(self, target: str, params: Dict[str, Any]) -> list:
        """Target may be a PID ("1234") or a process name ("notepad.exe")."""
        raw_pid = params.get("pid")
        if raw_pid not in (None, ""):
            try:
                return [int(raw_pid)]
            except (TypeError, ValueError):
                raise RuntimeError(f"Invalid PID: {raw_pid}")
        if not target:
            raise RuntimeError("terminate_process needs a PID or process name as target")
        if target.isdigit():
            return [int(target)]

        wanted = target.lower()
        if not wanted.endswith(".exe"):
            alt = wanted + ".exe"
        else:
            alt = wanted[:-4]
        pids = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = (proc.info.get("name") or "").lower()
            except Exception:
                continue
            if name in (wanted, alt) and proc.info["pid"] != self._self_pid:
                pids.append(proc.info["pid"])
        if not pids:
            raise RuntimeError(f"No running process named '{target}'")
        params.setdefault("process_name", target)
        return sorted(pids)

    @staticmethod
    def _validate_remote_ip(value: Any) -> str:
        """Only allow a single, specific IP (never 'any', 0.0.0.0, or a subnet)."""
        text = str(value or "").strip()
        if not text:
            raise RuntimeError("This action needs an IP address as target")
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            raise RuntimeError(f"'{text}' is not a valid IP address")
        if ip.is_unspecified or ip.is_loopback:
            raise RuntimeError(f"Refusing to block {text} (loopback/unspecified address)")
        return str(ip)

    @staticmethod
    def _is_current_user(user_id: str) -> bool:
        names = set()
        for getter in (lambda: os.getlogin(),
                       lambda: os.environ.get("USERNAME", ""),
                       lambda: os.environ.get("USER", "")):
            try:
                n = getter()
                if n:
                    names.add(n.lower())
            except Exception:
                pass
        uid = user_id.lower().split("\\")[-1]
        return uid in names

    # ============================================================
    # Action dispatch - wraps every handler with ActionRecord publishing
    # ============================================================

    async def _execute_action(self, action: ResponseAction, event: Event):
        handlers = {
            ResponseAction.ISOLATE_ASSET: self._isolate_asset_windows,
            ResponseAction.PSEUDO_LOCK: self._pseudo_lock_firewall,
            ResponseAction.REVOKE_IDENTITY: self._lock_user_account,
            ResponseAction.NOTIFY_SECURITY: self._send_alert,
            ResponseAction.TERMINATE_PROCESS: self._terminate_process,
            ResponseAction.ALLOW_ACCESS: self._allow_access,
            ResponseAction.BLOCK_ACCESS: self._block_access,
            ResponseAction.CHALLENGE_MFA: self._challenge_mfa,
            ResponseAction.REVOKE_SESSION: self._revoke_session,
            ResponseAction.QUARANTINE_DEVICE: self._quarantine_device,
            ResponseAction.FORCE_LOGOUT: self._force_logout,
            ResponseAction.STEP_UP_AUTH: self._step_up_auth,
            ResponseAction.GRANT_TEMP_PRIVILEGE: self._grant_temp_privilege,
            ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION: self._schedule_privilege_revocation,
            ResponseAction.RESTRICT_IDENTITY: self._restrict_identity,
            ResponseAction.LIFT_RESTRICTION: self._lift_restriction,
            ResponseAction.THROTTLE_SEGMENT: self._throttle_segment,
            ResponseAction.REMOVE_THROTTLE: self._remove_throttle,
        }
        handler = handlers.get(action)
        if not handler:
            log.warning("No handler for action: %s", action.value)
            return None

        # 1) PENDING record so the tab shows the action instantly
        record = self._build_action_record(action, event)
        await self._publish_action(record)

        # 2) Run the real handler (a handler may return a details string)
        try:
            result = await handler(event)
            if isinstance(result, str) and result:
                record.details = result
            elif isinstance(result, dict):
                record.details = str(result.get("details") or record.details or "")
                record.metadata.update(result.get("metadata") or {})
        except Exception as exc:
            record.status = ActionStatus.FAILED.value
            record.success = False
            record.error = f"{type(exc).__name__}: {exc}"
            record.details = record.details or f"{action.value} failed"
            await self._publish_action(record)
            log.error(
                "Action %s FAILED for event %s: %s",
                action.value, event.event_id, record.error,
            )
            return record

        # 3) Finalise
        _, final_status = _ACTION_META.get(action, ("unknown", ActionStatus.SUCCESS))
        if final_status == ActionStatus.ACTIVE:
            record.status = ActionStatus.ACTIVE.value
            record.details = record.details or f"{action.value} deployed and active"
        else:
            record.status = ActionStatus.SUCCESS.value
            record.details = record.details or f"{action.value} completed"
        record.success = True
        record.error = None
        await self._publish_action(record)
        return record

    # ============================================================
    # ActionRecord helpers
    # ============================================================

    async def _publish_action(self, record: ActionRecord) -> None:
        try:
            result = self.bus.publish(record)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            log.warning("Failed to publish ActionRecord %s: %s", record.action_id, exc)

    def _build_action_record(self, action: ResponseAction, event: Event) -> ActionRecord:
        target_type, _ = _ACTION_META.get(action, ("unknown", ActionStatus.SUCCESS))
        target, extra_meta = self._extract_target(action, event)

        severity = "high"
        sev = getattr(event, "severity", None)
        if sev is not None:
            severity = sev.value if hasattr(sev, "value") else str(sev).lower()

        # GateDecision has .reason; AgentFinding has .summary
        reason = (
            getattr(event, "reason", None)
            or getattr(event, "summary", None)
            or ""
        )

        metadata: Dict[str, Any] = {}
        gate = getattr(event, "gate", None)
        if gate is not None:
            metadata["gate"] = gate.value if hasattr(gate, "value") else gate
        verdict = getattr(event, "verdict", None)
        if verdict is not None:
            metadata["verdict"] = verdict.value if hasattr(verdict, "value") else verdict
        threat = getattr(event, "threat_type", None)
        if threat is not None:
            metadata["threat_type"] = threat.value if hasattr(threat, "value") else str(threat)
        metadata.update(extra_meta)
        ev_meta = getattr(event, "metadata", None) or {}
        if ev_meta.get("remote"):
            metadata["remote"] = True
            metadata["triggered_from"] = "dashboard"
            if ev_meta.get("cmd_id"):
                metadata["cmd_id"] = ev_meta["cmd_id"]

        return ActionRecord(
            action_id=f"act_{uuid.uuid4().hex[:12]}",
            action=action.value,
            target=target,
            target_type=target_type,
            status=ActionStatus.PENDING.value,
            details="",
            reason=str(reason),
            agent_name="RealResponseEngine",
            severity=severity,
            triggered_by=event.event_id,
            success=True,
            metadata=metadata,
        )

    def _extract_target(self, action: ResponseAction, event: Event) -> tuple:
        payload = (event.metadata or {}).get("payload", {}) or {}
        raw = payload.get("raw_payload", {}) or {}

        def _pick(*keys, default=None):
            for k in keys:
                for container in (payload, raw, event.metadata or {}):
                    v = container.get(k)
                    if v not in (None, "", "unknown"):
                        return v
            return default

        if action == ResponseAction.TERMINATE_PROCESS:
            pid = self._extract_pid(event)
            name = _pick("process_name", "name", "image", default="unknown")
            if pid:
                return f"{name} (PID: {pid})", {"pid": pid, "process_name": name}
            return str(name), {"process_name": name}

        if action in (ResponseAction.ISOLATE_ASSET,
                      ResponseAction.BLOCK_ACCESS,
                      ResponseAction.ALLOW_ACCESS):
            ip = _pick("src_ip", "ip", "remote_ip")
            if ip:
                return str(ip), {"src_ip": ip}
            return event.event_id, {}

        if action == ResponseAction.QUARANTINE_DEVICE:
            device_id = _pick("device_id")
            if not device_id:
                device_info = payload.get("device_info") or raw.get("device_info") or {}
                device_id = device_info.get("device_id")
            if device_id:
                return str(device_id), {"device_id": device_id}
            return event.event_id, {}

        if action in (ResponseAction.THROTTLE_SEGMENT, ResponseAction.REMOVE_THROTTLE):
            seg = _pick("segment", "src_ip", "ip")
            return (str(seg), {"segment": seg}) if seg else (event.event_id, {})

        if action in (
            ResponseAction.REVOKE_IDENTITY,
            ResponseAction.RESTRICT_IDENTITY,
            ResponseAction.LIFT_RESTRICTION,
            ResponseAction.FORCE_LOGOUT,
            ResponseAction.REVOKE_SESSION,
            ResponseAction.CHALLENGE_MFA,
            ResponseAction.STEP_UP_AUTH,
            ResponseAction.GRANT_TEMP_PRIVILEGE,
            ResponseAction.SCHEDULE_PRIVILEGE_REVOCATION,
        ):
            user_id = self._extract_user_id(event)
            if user_id:
                return str(user_id), {"user_id": user_id}
            return event.event_id, {}

        if action == ResponseAction.PSEUDO_LOCK:
            subject = self._extract_user_id(event) or _pick("src_ip", "ip") or event.event_id
            return str(subject), {}

        return event.event_id, {}

    # ============================================================
    # Process kill safety
    # ============================================================

    def _extract_pid(self, event: Event) -> Optional[int]:
        payload = (event.metadata or {}).get("payload", {}) or {}
        raw = payload.get("raw_payload", {}) or {}
        for container in (payload, raw, event.metadata or {}):
            pid = container.get("pid")
            if pid:
                try:
                    return int(pid)
                except (ValueError, TypeError):
                    continue
        return None

    def _is_kill_allowed(self, pid: int) -> tuple[bool, str]:
        """
        Returns (allowed, reason). Refuses to kill:
          * our own process
          * our parent process
          * pid 0 (System Idle / scheduler) and pid 4 (System on Windows)
          * any process on the protect list
        """
        if pid <= 4:
            return False, f"pid {pid} is a system-reserved process"

        if pid == self._self_pid:
            return False, "refusing to kill our own agent process"

        if self._parent_pid and pid == self._parent_pid:
            return False, "refusing to kill our parent process"

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return False, "process already exited"
        except psutil.AccessDenied:
            return False, "access denied reading process info"
        except Exception as exc:
            return False, f"could not inspect process: {exc}"

        try:
            name = (proc.name() or "").lower()
        except Exception:
            name = ""

        if name and name in _PROTECTED_PROCESS_NAMES:
            return False, f"'{name}' is on the protect list"

        return True, "ok"

    # ============================================================
    # Handlers
    # ============================================================

    async def _isolate_asset_windows(self, event: Event):
        payload = (event.metadata or {}).get("payload", {}) or {}
        src_ip = payload.get("src_ip")
        if not src_ip or src_ip == "unknown":
            raw = payload.get("raw_payload", {}) or {}
            src_ip = raw.get("src_ip")
        if not src_ip:
            raise RuntimeError("Cannot isolate: missing source IP")

        rule_name = f"AiBoO_Isolate_{src_ip}_{event.event_id}"
        rule_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", f"remoteip={src_ip}",
            "action=block", "protocol=any",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout isolating {src_ip}")
        if result.returncode != 0:
            raise RuntimeError(
                f"netsh failed for {src_ip}: {(result.stderr or result.stdout).strip()}"
            )
        log.warning("Isolated IP %s via Windows Firewall", src_ip)

    async def _pseudo_lock_firewall(self, event: Event):
        provider = self.pseudo_lock_provider
        if provider is None:
            log.warning("Pseudo-lock requested for event %s but no decoy provider is running",
                        event.event_id)
            raise RuntimeError("Pseudo-lock agent is not running on this endpoint")
        lock_id = f"lock_{event.event_id}"
        record = await provider.open_lock(lock_id, event)
        log.warning("Pseudo-lock active for event %s (decoy %s)", event.event_id, record.decoy_endpoint)
        return {
            "details": f"Decoy listening on {record.decoy_endpoint} (lock {lock_id})",
            "metadata": {"lock_id": lock_id, "decoy_port": record.decoy_port},
        }

    async def _lock_user_account(self, event: Event):
        payload = (event.metadata or {}).get("payload", {}) or {}
        user_id = payload.get("user_id")
        if not user_id or user_id == "unknown":
            raw = payload.get("raw_payload", {}) or {}
            user_id = raw.get("user_id")
        if not user_id:
            raise RuntimeError("Cannot lock user: missing user_id")
        if not _validate_user_id(user_id):
            raise RuntimeError(f"Invalid user_id format: {user_id}")
        user_id = _to_local_account_name(user_id)
        _refuse_if_self_or_system(user_id)

        cmd = ["net", "user", user_id, "/active:no"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout locking user {user_id}")
        if result.returncode != 0:
            raise RuntimeError(
                f"net user failed: {(result.stderr or result.stdout).strip()}"
            )
        log.warning("Locked user account: %s", user_id)
        # Double-check so the dashboard never says "Success" for nothing.
        try:
            check = subprocess.run(["net", "user", user_id], capture_output=True,
                                   text=True, timeout=10)
            for line in (check.stdout or "").splitlines():
                if line.lower().startswith("account active"):
                    state = line.split()[-1]
                    if state.lower() in ("yes", "ja", "oui", "sí", "si"):
                        raise RuntimeError(
                            f"Windows still reports '{user_id}' as active after net user /active:no")
                    return f"Account '{user_id}' disabled (verified: Account active = {state})"
        except RuntimeError:
            raise
        except Exception:
            pass
        return f"Account '{user_id}' disabled (net user /active:no)"

    async def _send_alert(self, event: Event):
        log.warning("Security alert sent for event %s", event.event_id)

    async def _terminate_process(self, event: Event):
        """
        Real process termination.

        Raises on failure so the dispatch wrapper marks the ActionRecord as
        FAILED, which is what the dashboard shows. Never returns quietly on
        error - silent success is what makes EDRs untrustworthy.
        """
        payload = (event.metadata or {}).get("payload", {}) or {}
        raw = payload.get("raw_payload", {}) or {}

        pid = self._extract_pid(event)
        process_name = (
            payload.get("process_name")
            or raw.get("process_name")
            or "unknown"
        )

        if not pid:
            raise RuntimeError(
                f"Cannot terminate: no PID found for {process_name}"
            )

        # Never-kill enforcement (also runs in _on_finding, but
        # _execute_action can be called directly from Gate 3 decisions
        # or remote commands, so we re-check here).
        allowed, reason = self._is_kill_allowed(pid)
        if not allowed:
            raise RuntimeError(f"Kill refused for pid {pid}: {reason}")

        # DRY RUN
        if self._dry_run:
            log.warning(
                "[dry-run] Would terminate pid %s (%s)", pid, process_name
            )
            return

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            raise RuntimeError(f"Process {pid} does not exist (already gone?)")
        except psutil.AccessDenied:
            raise RuntimeError(
                f"Access denied reading pid {pid} - run agent as Administrator"
            )

        try:
            real_name = proc.name()
        except Exception:
            real_name = process_name

        log.warning("Terminating suspicious process: %s (PID: %s)", real_name, pid)

        # Graceful terminate, then hard kill if it lingers
        try:
            proc.terminate()
        except psutil.AccessDenied:
            raise RuntimeError(
                f"Access denied terminating {real_name} ({pid}) - "
                f"run agent as Administrator/SYSTEM"
            )
        except Exception as exc:
            raise RuntimeError(f"terminate() failed for {pid}: {exc}")

        def _gone() -> bool:
            # A killed process can linger as a zombie until its parent
            # reaps it - it is no longer running, so count it as gone.
            try:
                return (not proc.is_running()) or proc.status() == psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                return True

        # Wait without blocking the event loop (other commands, heartbeats)
        try:
            await asyncio.to_thread(proc.wait, 2)
        except psutil.TimeoutExpired:
            if not _gone():
                log.warning("Process %s ignored terminate, force-killing", pid)
                try:
                    proc.kill()
                    await asyncio.to_thread(proc.wait, 2)
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    raise RuntimeError(
                        f"Access denied force-killing {real_name} ({pid})"
                    )
                except psutil.TimeoutExpired:
                    pass  # checked by _gone() below
                except Exception as exc:
                    raise RuntimeError(f"kill() failed for {pid}: {exc}")
        except psutil.NoSuchProcess:
            pass
        except Exception as exc:
            raise RuntimeError(f"wait() failed for {pid}: {exc}")

        if not _gone():
            raise RuntimeError(
                f"Process {real_name} ({pid}) is still running after kill"
            )

        log.warning(
            "Process terminated successfully: %s (PID: %s)", real_name, pid
        )

    # ============================================================
    # Zero Trust handlers (unchanged in behavior)
    # ============================================================

    async def _allow_access(self, event: Event):
        log.info("Access allowed for %s", event.event_id)

    async def _block_access(self, event: Event):
        payload = (event.metadata or {}).get("payload", {}) or {}
        src_ip = payload.get("src_ip") or payload.get("ip")
        if not src_ip:
            raw = payload.get("raw_payload", {}) or {}
            src_ip = raw.get("src_ip")
        if not src_ip:
            raise RuntimeError("Cannot block: missing source IP")

        rule_name = f"AiBoO_Block_{src_ip}_{event.event_id}"
        rule_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", f"remoteip={src_ip}",
            "action=block", "protocol=any",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout blocking {src_ip}")
        if result.returncode != 0:
            raise RuntimeError(
                f"netsh failed for {src_ip}: {(result.stderr or result.stdout).strip()}"
            )
        log.warning("Blocked IP %s via Windows Firewall", src_ip)

    # ---- Dynamic access control (real Windows changes, see access_control.py) ----

    @staticmethod
    def _access_control():
        from response.access_control import get_access_control
        return get_access_control()

    def _payload_value(self, event: Event, key: str):
        payload = (event.metadata or {}).get("payload", {}) or {}
        v = payload.get(key)
        if v in (None, ""):
            v = (payload.get("raw_payload", {}) or {}).get(key)
        if v in (None, ""):
            v = (event.metadata or {}).get(key)
        return v

    def _require_user(self, event: Event, what: str) -> str:
        user_id = self._extract_user_id(event)
        if not user_id or user_id == "unknown":
            raise RuntimeError(f"Cannot {what}: no user name in this alert")
        if not _validate_user_id(user_id):
            raise RuntimeError(f"Invalid user_id format: {user_id}")
        return user_id

    async def _restrict_identity(self, event: Event):
        user_id = self._require_user(event, "restrict the account")
        minutes = self._payload_value(event, "minutes") or 30
        reason = getattr(event, "reason", "") or getattr(event, "summary", "") or ""
        return await asyncio.to_thread(self._access_control().restrict_identity, user_id, minutes, reason)

    async def _lift_restriction(self, event: Event):
        user_id = self._require_user(event, "lift the restriction")
        return await asyncio.to_thread(self._access_control().lift_restriction, user_id)

    async def _throttle_segment(self, event: Event):
        seg = self._payload_value(event, "segment") or self._payload_value(event, "src_ip")
        if not seg:
            raise RuntimeError("Cannot throttle: no IP address / range given")
        return await asyncio.to_thread(self._access_control().throttle, seg,
                                       self._payload_value(event, "kbps") or 256,
                                       self._payload_value(event, "minutes") or 30)

    async def _remove_throttle(self, event: Event):
        seg = self._payload_value(event, "segment") or self._payload_value(event, "src_ip")
        if not seg:
            raise RuntimeError("Cannot remove throttle: no IP address / range given")
        return await asyncio.to_thread(self._access_control().remove_throttle, seg)

    async def _challenge_mfa(self, event: Event):
        # Windows has no MFA prompt of its own: locking the screen forces the
        # person at the keyboard to prove who they are (password / PIN / Hello).
        return await asyncio.to_thread(self._access_control().lock_screen)

    async def _step_up_auth(self, event: Event):
        return await asyncio.to_thread(self._access_control().lock_screen)

    async def _logoff(self, event: Event):
        user_id = self._require_user(event, "log off")
        name = user_id.split("\\")[-1]
        sessions = await asyncio.to_thread(self._access_control().logoff_user, name)
        return f"Logged off '{name}' ({len(sessions)} session(s): {', '.join(map(str, sessions))})"

    async def _revoke_session(self, event: Event):
        return await self._logoff(event)

    async def _force_logout(self, event: Event):
        return await self._logoff(event)

    async def _quarantine_device(self, event: Event):
        # Honest: there is no network-access-control system connected, so we
        # do not pretend. Use Isolate Host (firewall) or Throttle Segment.
        raise RuntimeError(
            "Device quarantine needs a network access control (NAC) / switch integration, which is "
            "not connected. Use 'Isolate Host' (firewall block) or 'Throttle Segment' instead.")

    async def _grant_temp_privilege(self, event: Event):
        user_id = self._extract_user_id(event)
        if not user_id:
            raise RuntimeError("Cannot grant privilege: missing user ID")
        if not _validate_user_id(user_id):
            raise RuntimeError(f"Invalid user_id format: {user_id}")

        payload = (event.metadata or {}).get("payload", {}) or {}
        duration_minutes = payload.get("jit_duration_minutes", 15)
        expiry = datetime.now() + timedelta(minutes=duration_minutes)
        self._active_jit_grants[user_id] = {
            "granted_at": datetime.now(),
            "expires_at": expiry,
            "duration": duration_minutes,
            "event_id": event.event_id,
        }
        log.warning(
            "JIT privilege granted to %s for %s min (expires at %s)",
            user_id, duration_minutes, expiry,
        )
        cmd = ["net", "localgroup", "Administrators", user_id, "/add"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout granting privilege to {user_id}")
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to add {user_id}: {(result.stderr or result.stdout).strip()}"
            )
        log.warning("Added %s to Administrators group (JIT)", user_id)

    async def _schedule_privilege_revocation(self, event: Event):
        user_id = self._extract_user_id(event)
        if not user_id:
            return
        grant = self._active_jit_grants.get(user_id)
        if not grant:
            log.warning(
                "No active JIT grant for %s, cannot schedule revocation", user_id
            )
            return
        expiry = grant["expires_at"]
        log.warning("Scheduled privilege revocation for %s at %s", user_id, expiry)
        asyncio.create_task(self._revoke_privilege_at(user_id, expiry))

    async def _revoke_privilege_at(self, user_id: str, expiry: datetime):
        now = datetime.now()
        wait_seconds = (expiry - now).total_seconds()
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)
        log.warning("Revoking JIT privilege for %s (expired)", user_id)
        cmd = ["net", "localgroup", "Administrators", user_id, "/delete"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Removed %s from Administrators (JIT expired)", user_id)
            else:
                log.error(
                    "Failed to remove %s: %s",
                    user_id, (result.stderr or result.stdout).strip(),
                )
        except Exception as e:
            log.error("Error removing user from Administrators: %s", e)
        self._active_jit_grants.pop(user_id, None)

    # ============================================================
    # Helpers
    # ============================================================

    def _extract_user_id(self, event: Event) -> Optional[str]:
        payload = (event.metadata or {}).get("payload", {}) or {}
        user_id = payload.get("user_id")
        if not user_id:
            raw = payload.get("raw_payload", {}) or {}
            user_id = raw.get("user_id")
        if not user_id:
            user_id = (event.metadata or {}).get("user_id")
        return user_id

    def stop(self):
        log.info("RealResponseEngine stopped")