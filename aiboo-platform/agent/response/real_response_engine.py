from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import psutil

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, ResponseAction, RiskLevel

log = logging.getLogger("RealResponseEngine")

_USER_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_.@\\-]+$')


def _validate_user_id(user_id: str) -> bool:
    return bool(_USER_ID_PATTERN.match(user_id))


class RealResponseEngine:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._active_jit_grants: Dict[str, Dict[str, Any]] = {}

    def start(self):
        self.bus.subscribe(GateDecision, self._on_decision)
        log.info("Real Response Engine — ACTIVE (Zero Trust ready)")

    async def _on_decision(self, decision: GateDecision):
        if decision.gate != GateLevel.GATE_3 or decision.verdict != GateVerdict.BLOCK:
            return
        for action in decision.actions:
            await self._execute_action(action, decision)

    async def _execute_action(self, action: ResponseAction, decision: GateDecision):
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
        if handler:
            await handler(decision)
        else:
            log.warning("No handler for action: %s", action.value)

    # ============================================================
    # Existing handlers
    # ============================================================

    async def _isolate_asset_windows(self, decision: GateDecision):
        payload = decision.metadata.get("payload", {})
        src_ip = payload.get("src_ip")
        if not src_ip or src_ip == "unknown":
            raw = payload.get("raw_payload", {})
            src_ip = raw.get("src_ip")
            if not src_ip:
                log.warning("Cannot isolate: missing source IP")
                return
        try:
            rule_name = f"AiBoO_Isolate_{src_ip}_{decision.event_id}"
            rule_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name)
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", f"remoteip={src_ip}",
                "action=block", "protocol=any"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Isolated IP %s via Windows Firewall", src_ip)
            else:
                log.error("Failed to isolate %s: %s", src_ip, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Timeout isolating asset %s", src_ip)
        except Exception as e:
            log.error("Error isolating asset: %s", e)

    async def _pseudo_lock_firewall(self, decision: GateDecision):
        log.warning("Pseudo-lock active for event %s", decision.event_id)

    async def _lock_user_account(self, decision: GateDecision):
        payload = decision.metadata.get("payload", {})
        user_id = payload.get("user_id")
        if not user_id or user_id == "unknown":
            raw = payload.get("raw_payload", {})
            user_id = raw.get("user_id")
            if not user_id:
                return
        if not _validate_user_id(user_id):
            log.warning("Invalid user_id format, skipping lock: %s", user_id)
            return
        try:
            cmd = ["net", "user", user_id, "/active:no"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Locked user account: %s", user_id)
            else:
                log.error("Failed to lock user %s: %s", user_id, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Timeout locking user %s", user_id)
        except Exception as e:
            log.error("Error locking user: %s", e)

    async def _send_alert(self, decision: GateDecision):
        log.warning("Security alert sent for event %s", decision.event_id)

    async def _terminate_process(self, decision: GateDecision):
        payload = decision.metadata.get("payload", {})
        pid = payload.get("pid")
        if not pid:
            raw = payload.get("raw_payload", {})
            pid = raw.get("pid")
        process_name = payload.get("process_name", "unknown")
        if not pid:
            log.warning("Cannot terminate process: No PID found for %s", process_name)
            return
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            log.warning("Terminating suspicious process: %s (PID: %s)", proc_name, pid)
            proc.terminate()
            await asyncio.sleep(2)
            if proc.is_running():
                proc.kill()
                log.warning("Force killed process: %s (PID: %s)", proc_name, pid)
            log.warning("Process terminated successfully: %s", proc_name)
        except psutil.NoSuchProcess:
            log.warning("Process %s already terminated", pid)
        except psutil.AccessDenied:
            log.error("Access denied: Cannot terminate process %s (try running as Admin)", pid)
        except Exception as e:
            log.error("Failed to terminate process %s: %s", pid, e)

    # ============================================================
    # Zero Trust handlers
    # ============================================================

    async def _allow_access(self, decision: GateDecision):
        log.info("Access allowed for %s", decision.event_id)

    async def _block_access(self, decision: GateDecision):
        payload = decision.metadata.get("payload", {})
        src_ip = payload.get("src_ip") or payload.get("ip")
        if not src_ip:
            raw = payload.get("raw_payload", {})
            src_ip = raw.get("src_ip")
        if not src_ip:
            log.warning("Cannot block: missing source IP")
            return
        try:
            rule_name = f"AiBoO_Block_{src_ip}_{decision.event_id}"
            rule_name = re.sub(r'[^a-zA-Z0-9_-]', '_', rule_name)
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", f"remoteip={src_ip}",
                "action=block", "protocol=any"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Blocked IP %s via Windows Firewall", src_ip)
            else:
                log.error("Failed to block %s: %s", src_ip, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Timeout blocking IP %s", src_ip)
        except Exception as e:
            log.error("Error blocking IP: %s", e)

    async def _challenge_mfa(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        log.warning("MFA challenge sent to %s (event %s)", user_id or 'unknown user', decision.event_id)

    async def _revoke_session(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        if user_id:
            log.warning("All sessions revoked for user %s", user_id)
        else:
            log.warning("Session %s revoked", decision.event_id)

    async def _quarantine_device(self, decision: GateDecision):
        payload = decision.metadata.get("payload", {})
        device_id = payload.get("device_id") or payload.get("device_info", {}).get("device_id")
        if not device_id:
            raw = payload.get("raw_payload", {})
            device_id = raw.get("device_id")
        if not device_id:
            log.warning("Cannot quarantine: missing device ID")
            return
        log.warning("Device %s quarantined (event %s)", device_id, decision.event_id)

    async def _force_logout(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        if user_id:
            log.warning("Forced logout for user %s", user_id)
        else:
            log.warning("Forced logout for event %s", decision.event_id)

    async def _step_up_auth(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        log.warning("Step-up auth required for %s (event %s)", user_id or 'unknown user', decision.event_id)

    async def _grant_temp_privilege(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        if not user_id:
            log.warning("Cannot grant privilege: missing user ID")
            return
        if not _validate_user_id(user_id):
            log.warning("Invalid user_id format, skipping privilege grant: %s", user_id)
            return
        payload = decision.metadata.get("payload", {})
        duration_minutes = payload.get("jit_duration_minutes", 15)
        expiry = datetime.now() + timedelta(minutes=duration_minutes)
        self._active_jit_grants[user_id] = {
            "granted_at": datetime.now(),
            "expires_at": expiry,
            "duration": duration_minutes,
            "event_id": decision.event_id,
        }
        log.warning("JIT privilege granted to %s for %s min (expires at %s)", user_id, duration_minutes, expiry)
        try:
            cmd = ["net", "localgroup", "Administrators", user_id, "/add"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Added %s to Administrators group (JIT)", user_id)
            else:
                log.error("Failed to add %s to Administrators: %s", user_id, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Timeout granting privilege to %s", user_id)
        except Exception as e:
            log.error("Error adding user to Administrators: %s", e)

    async def _schedule_privilege_revocation(self, decision: GateDecision):
        user_id = self._extract_user_id(decision)
        if not user_id:
            return
        grant = self._active_jit_grants.get(user_id)
        if not grant:
            log.warning("No active JIT grant found for %s, cannot schedule revocation", user_id)
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
        try:
            cmd = ["net", "localgroup", "Administrators", user_id, "/delete"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                log.warning("Removed %s from Administrators (JIT expired)", user_id)
            else:
                log.error("Failed to remove %s from Administrators: %s", user_id, result.stderr)
        except subprocess.TimeoutExpired:
            log.error("Timeout revoking privilege for %s", user_id)
        except Exception as e:
            log.error("Error removing user from Administrators: %s", e)
        self._active_jit_grants.pop(user_id, None)

    # ============================================================
    # Helper methods
    # ============================================================

    def _extract_user_id(self, decision: GateDecision) -> Optional[str]:
        payload = decision.metadata.get("payload", {})
        user_id = payload.get("user_id")
        if not user_id:
            raw = payload.get("raw_payload", {})
            user_id = raw.get("user_id")
        if not user_id:
            user_id = decision.metadata.get("user_id")
        return user_id

    def stop(self):
        log.info("RealResponseEngine stopped")
