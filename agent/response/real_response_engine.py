from __future__ import annotations

import asyncio
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


# ---------------------------------------------------------------------------
# Never-kill list — processes whose termination would BSOD, break the OS,
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
            AIBOO_AUTO_TERMINATE=0|1          (default: 1 — enabled)
            AIBOO_AUTO_TERMINATE_SEVERITIES   (default: "high,critical")
            AIBOO_AUTO_TERMINATE_MIN_CONF     (default: "0.8")
            AIBOO_DRY_RUN=1                   (skip actual kills, log only)

    Remote execution:
        execute_remote_action() is the entry point for commands pushed by the
        backend over the CommandChannel WebSocket. It wraps the incoming
        command in a synthetic AgentFinding so the normal _execute_action
        pipeline runs unchanged — ActionRecords get published, DashboardBridge
        forwards them, the dashboard shows the row.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._active_jit_grants: Dict[str, Dict[str, Any]] = {}

        # ---- Auto-termination policy ----
        self._auto_terminate_enabled = os.getenv(
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
                "AUTO-TERMINATE ENABLED — severities=%s, min_confidence=%.2f, "
                "dry_run=%s",
                sorted(self._auto_terminate_severities),
                self._auto_terminate_min_confidence,
                self._dry_run,
            )
        else:
            log.info("Auto-terminate disabled (set AIBOO_AUTO_TERMINATE=1 to enable)")

    def start(self):
        self.bus.subscribe(GateDecision, self._on_decision)
        self.bus.subscribe(AgentFinding, self._on_finding)
        log.info("Real Response Engine — ACTIVE (Zero Trust + auto-response)")

    # ============================================================
    # Event handlers
    # ============================================================

    async def _on_decision(self, decision: GateDecision):
        """Gate 3 BLOCK → run every action in the decision."""
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
            "AUTO-TERMINATE → pid=%s threat=%s severity=%s confidence=%.2f",
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
    ) -> None:
        """
        Entry point for commands pushed via the CommandChannel WebSocket.

        Wraps the incoming action in a synthetic AgentFinding so the normal
        _execute_action pipeline runs unchanged — ActionRecords get published,
        DashboardBridge forwards them, the dashboard shows the row.

        Called by CommandChannel._handle_command() when the backend
        dispatches a remote action to this endpoint.

        Args:
            action_name: ResponseAction value string, e.g. "terminate_process"
            target:      target identifier (pid / ip / user_id / device_id)
            params:      optional dict — pid, src_ip, user_id, device_id,
                         process_name, severity, confidence, etc.
        """
        params = params or {}

        try:
            action = ResponseAction(action_name)
        except ValueError:
            log.error("Unknown remote action: %s", action_name)
            raise RuntimeError(f"Unknown action: {action_name}")

        log.warning(
            "REMOTE ACTION → %s (target=%s)", action.value, target,
        )

        # Build a payload that the existing _extract_* helpers understand.
        # The helpers look for pid / src_ip / user_id / device_id in
        # metadata.payload, metadata.payload.raw_payload, or metadata directly.
        payload: Dict[str, Any] = {
            "target": target,
            "src_ip": params.get("src_ip") or target,
            "pid": params.get("pid"),
            "user_id": params.get("user_id") or target,
            "device_id": params.get("device_id") or target,
            "process_name": params.get("process_name"),
            "jit_duration_minutes": params.get("jit_duration_minutes"),
        }

        # Only keep keys with real values so _pick() falls through cleanly
        payload = {k: v for k, v in payload.items() if v not in (None, "")}

        severity_value = str(params.get("severity", "high")).lower()
        try:
            severity = Severity(severity_value)
        except ValueError:
            severity = Severity.HIGH

        confidence = float(params.get("confidence", 1.0))

        synthetic = AgentFinding(
            agent_name="RemoteCommand",
            event_id=f"remote_{uuid.uuid4().hex[:8]}",
            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
            severity=severity,
            confidence=confidence,
            summary=f"Remote command from dashboard: {action.value} → {target}",
            actions=[action],
            metadata={
                "payload": payload,
                "remote": True,
                "target": target,
                **{k: v for k, v in params.items() if k not in payload},
            },
        )

        await self._execute_action(action, synthetic)

    # ============================================================
    # Action dispatch — wraps every handler with ActionRecord publishing
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
        }
        handler = handlers.get(action)
        if not handler:
            log.warning("No handler for action: %s", action.value)
            return

        # 1) PENDING record so the tab shows the action instantly
        record = self._build_action_record(action, event)
        await self._publish_action(record)

        # 2) Run the real handler
        try:
            await handler(event)
        except Exception as exc:
            record.status = ActionStatus.FAILED.value
            record.success = False
            record.error = f"{type(exc).__name__}: {exc}"
            record.details = record.details or f"{action.value} failed"
            await self._publish_action(record)
            log.exception(
                "Action %s FAILED for event %s", action.value, event.event_id
            )
            return

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

        if action in (
            ResponseAction.REVOKE_IDENTITY,
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
        log.warning("Pseudo-lock active for event %s", event.event_id)

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

    async def _send_alert(self, event: Event):
        log.warning("Security alert sent for event %s", event.event_id)

    async def _terminate_process(self, event: Event):
        """
        Real process termination.

        Raises on failure so the dispatch wrapper marks the ActionRecord as
        FAILED, which is what the dashboard shows. Never returns quietly on
        error — silent success is what makes EDRs untrustworthy.
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
                f"Access denied reading pid {pid} — run agent as Administrator"
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
                f"Access denied terminating {real_name} ({pid}) — "
                f"run agent as Administrator/SYSTEM"
            )
        except Exception as exc:
            raise RuntimeError(f"terminate() failed for {pid}: {exc}")

        try:
            proc.wait(timeout=2)
        except psutil.TimeoutExpired:
            log.warning("Process %s ignored SIGTERM, force-killing", pid)
            try:
                proc.kill()
                proc.wait(timeout=2)
            except psutil.AccessDenied:
                raise RuntimeError(
                    f"Access denied force-killing {real_name} ({pid})"
                )
            except Exception as exc:
                raise RuntimeError(f"kill() failed for {pid}: {exc}")
        except Exception as exc:
            raise RuntimeError(f"wait() failed for {pid}: {exc}")

        if proc.is_running():
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

    async def _challenge_mfa(self, event: Event):
        user_id = self._extract_user_id(event)
        log.warning(
            "MFA challenge sent to %s (event %s)",
            user_id or "unknown user", event.event_id,
        )

    async def _revoke_session(self, event: Event):
        user_id = self._extract_user_id(event)
        if user_id:
            log.warning("All sessions revoked for user %s", user_id)
        else:
            log.warning("Session %s revoked", event.event_id)

    async def _quarantine_device(self, event: Event):
        payload = (event.metadata or {}).get("payload", {}) or {}
        device_id = payload.get("device_id") or payload.get("device_info", {}).get("device_id")
        if not device_id:
            raw = payload.get("raw_payload", {}) or {}
            device_id = raw.get("device_id")
        if not device_id:
            raise RuntimeError("Cannot quarantine: missing device ID")
        log.warning("Device %s quarantined (event %s)", device_id, event.event_id)

    async def _force_logout(self, event: Event):
        user_id = self._extract_user_id(event)
        if user_id:
            log.warning("Forced logout for user %s", user_id)
        else:
            log.warning("Forced logout for event %s", event.event_id)

    async def _step_up_auth(self, event: Event):
        user_id = self._extract_user_id(event)
        log.warning(
            "Step-up auth required for %s (event %s)",
            user_id or "unknown user", event.event_id,
        )

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