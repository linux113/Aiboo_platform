"""backend_bridge.py — Forwards AiBoO agent events to the remote backend via offline queue."""

from __future__ import annotations
import asyncio
import json
import logging
import os
import socket
import configparser
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .event_bus import EventBus
from .events import (
    ActionRecord,
    AgentFinding,
    CorrelatedAlert,
    GateDecision,
    ResponseAction,
    PseudoLockUpdate,
)
from .config import config
from .alert_queue import OfflineQueueManager

log = logging.getLogger("DashboardBridge")


# ---------------------------------------------------------------------------
# Human-readable labels for the Isolation & Termination tab
# ---------------------------------------------------------------------------
ACTION_LABELS = {
    "terminate_process": "Process Terminated",
    "isolate_asset": "Asset Isolated",
    "quarantine_device": "Device Quarantined",
    "pseudo_lock": "Pseudo-Lock Deployed",
    "revoke_identity": "Identity Revoked",
    "block_access": "Access Blocked",
    "lock_zone": "Zone Locked",
    "force_logout": "Session Forced Logout",
    "quarantine_file": "File Quarantined",
    "restrict_identity": "Account Restricted (temporary)",
    "lift_restriction": "Account Restriction Lifted",
    "throttle_segment": "Network Segment Throttled",
    "remove_throttle": "Throttle Removed",
    "revoke_session": "Sessions Logged Off",
    "step_up_auth": "Screen Locked (re-authenticate)",
    "challenge_mfa": "Screen Locked (re-authenticate)",
}

# Actions that put the endpoint into a contained state.
# The frontend uses this flag for its "Isolated" / "Quarantined" filter chips.
CONTAINMENT_ACTIONS = {
    "isolate_asset",
    "quarantine_device",
    "lock_zone",
    "block_access",
}


def _get_config_value(section: str, key: str, default: str = None) -> str:
    """Read config from config.ini or environment variable."""
    try:
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.getcwd()
        config_path = os.path.join(base_dir, 'config.ini')
        if os.path.exists(config_path):
            cp = configparser.ConfigParser()
            cp.read(config_path)
            if cp.has_section(section) and cp.has_option(section, key):
                return cp.get(section, key)
    except Exception:
        pass
    env_key = key.upper()
    if env_key in os.environ:
        return os.environ[env_key]
    return default


def _serialize(obj):
    """Recursively serialize dataclasses, enums, and datetime objects."""
    if hasattr(obj, "value"):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(v) for v in obj]
    return obj


def _as_iso(value) -> str:
    """Best-effort ISO-8601 conversion."""
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    return str(value)


class DashboardBridge:
    """
    Forwards events to the backend via the offline queue.
    All events are saved locally (SQLite) and retried automatically.
    Also sends a heartbeat every 60 seconds.
    """

    def __init__(
        self,
        bus: EventBus,
        backend_url: Optional[str] = None,
        api_key: Optional[str] = None,
        endpoint_id: Optional[str] = None,
    ) -> None:
        self._bus = bus
        self._backend_url = (
            backend_url
            or _get_config_value('AIBOO', 'remote_url', 'http://localhost:4000')
        ).rstrip("/")
        self._api_key = api_key or _get_config_value('AIBOO', 'api_key', 'dev-key-change-in-production')
        self._endpoint_id = endpoint_id or _get_config_value('AIBOO', 'endpoint_name', socket.gethostname())

        # Set log level from config
        log_level = _get_config_value('AIBOO', 'log_level', 'INFO')
        logging.getLogger().setLevel(log_level.upper())

        # ---- FIX: Always create/initialize the queue with our config ----
        # The singleton will either be created or reused.
        self._queue = OfflineQueueManager(self._backend_url, self._api_key)

        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._subscriptions = []

        log.info(
            "DashboardBridge initialized: backend=%s, endpoint=%s",
            self._backend_url,
            self._endpoint_id,
        )

    def start(self) -> None:
        """Start the bridge: subscribe to events and launch heartbeat."""
        self._running = True

        # Subscribe to event types
        self._bus.subscribe(AgentFinding, self._on_finding)
        self._bus.subscribe(CorrelatedAlert, self._on_correlated)
        self._bus.subscribe(GateDecision, self._on_gate_decision)
        # NEW: every executed response action (isolate / terminate / quarantine / etc.)
        self._bus.subscribe(ActionRecord, self._on_action)
        self._bus.subscribe(PseudoLockUpdate, self._on_pseudo_lock_update)

        log.info(
            "DashboardBridge subscribed to AgentFinding, CorrelatedAlert, "
            "GateDecision, ActionRecord"
        )

        # Send an immediate heartbeat so the endpoint appears instantly
        asyncio.create_task(self._send_heartbeat())

        # Start the periodic heartbeat loop (every 60 seconds)
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._heartbeat_task.add_done_callback(
            lambda t: log.warning("Heartbeat task stopped: %s", t.exception()) if t.exception() else None
        )

        log.info("DashboardBridge active — forwarding events via offline queue")

    async def stop(self) -> None:
        """Stop the bridge and cancel heartbeat."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        for sub in self._subscriptions:
            self._bus.unsubscribe(sub)
        self._subscriptions.clear()

        log.info("DashboardBridge stopped")

    async def _send_heartbeat(self) -> None:
        """Send a single heartbeat to the backend (for immediate registration)."""
        payload = {
            "source": self._endpoint_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online",
        }
        await self._queue.add_to_endpoint("heartbeat", payload)
        log.debug("Heartbeat queued for %s", self._endpoint_id)

    async def _heartbeat_loop(self) -> None:
        """Send a heartbeat to the backend every 60 seconds."""
        while self._running:
            try:
                await asyncio.sleep(60)
                if not self._running:
                    break
                await self._send_heartbeat()
            except Exception as e:
                log.warning("Heartbeat error: %s", e)

    async def send(self, endpoint: str, payload: dict) -> None:
        """Queue any JSON report (agent-status, compliance, ...) for
        POST /api/agent/<endpoint>."""
        payload = dict(payload or {})
        payload["source"] = self._endpoint_id
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        await self._queue.add_to_endpoint(endpoint, json.loads(json.dumps(payload, default=str)))

    # ---- Event handlers ----

    async def _on_finding(self, event: AgentFinding) -> None:
        """Queue a finding (only high/critical)."""
        if event.severity.value not in ("high", "critical"):
            return

        payload = _serialize(event)
        # Normalise fields for the backend
        payload.pop("timestamp", None)
        payload["id"] = payload.pop("event_id", "")
        payload["timestamp"] = _as_iso(event.timestamp)
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        payload["source"] = self._endpoint_id

        await self._queue.add_to_endpoint("findings", payload)
        # Pseudo-lock rows are NOT created here any more: a finding only
        # *asks* for a lock. The row is created by _on_pseudo_lock_update
        # once PseudoLockAgent has really opened the decoy port.

    async def _on_pseudo_lock_update(self, event: PseudoLockUpdate) -> None:
        """A decoy port was really opened (active) or really closed."""
        if event.active:
            payload = {
                "lock_id": event.lock_id,
                "event_id": event.event_id,
                "agent": event.agent,
                "severity": (event.severity or "high").lower(),
                "summary": event.summary,
                "active": True,
                "locked_at": _as_iso(event.timestamp),
                "decoy_port": event.decoy_port,
                "decoy_endpoint": event.decoy_endpoint,
                "original_endpoint": event.original_endpoint,
                "source": self._endpoint_id,
            }
            await self._queue.add_to_endpoint("pseudo-lock", payload)
        else:
            payload = {
                "lock_id": event.lock_id,
                "restored_at": _as_iso(event.timestamp),
                "decoy_port": event.decoy_port,
                "hits": event.hits,
                "message": event.message,
                "source": self._endpoint_id,
            }
            await self._queue.add_to_endpoint("pseudo-lock-restore", payload)

    async def _on_correlated(self, event: CorrelatedAlert) -> None:
        payload = _serialize(event)
        payload["alert_id"] = str(payload.get("alert_id", ""))
        payload["timestamp"] = _as_iso(event.timestamp)
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        payload["description"] = payload.get("description") or payload.get("summary", "")
        payload["source"] = self._endpoint_id
        incident = getattr(event, "incident", None)
        if isinstance(incident, dict):
            payload["incident"] = incident
        # the dashboard keys linked items by `id` (AgentFinding has event_id)
        for f in payload.get("findings") or []:
            if isinstance(f, dict):
                f.setdefault("id", f.get("event_id", ""))
                if isinstance(f.get("timestamp"), datetime):
                    f["timestamp"] = f["timestamp"].isoformat()
        await self._queue.add_to_endpoint("correlated", payload)

    async def _on_gate_decision(self, event: GateDecision) -> None:
        # Only the FINAL TriGate decision (Gate 3) goes to the dashboard: it
        # already carries all three gate results (Trust / Intent / Impact)
        # in metadata["trigate"]. Gate 1/2 decisions are intermediate steps.
        if int(getattr(event.gate, "value", event.gate)) != 3:
            return
        payload = _serialize(event)
        payload["gate"] = 3
        payload["gate_label"] = "TriGate"
        payload["timestamp"] = _as_iso(event.timestamp)
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        payload["source"] = self._endpoint_id
        payload["endpoint"] = self._endpoint_id
        await self._queue.add_to_endpoint("gate-decision", payload)

    # ------------------------------------------------------------------
    # NEW: Response action forwarding — powers the "Isolation & Termination" tab
    # ------------------------------------------------------------------

    async def _on_action(self, event: ActionRecord) -> None:
        """
        Queue a response action for the backend.

        Every action is forwarded regardless of status (pending / success /
        failed / active) so the "Isolation & Termination" tab can show
        in-flight and failed operations too — not just successes.
        """
        try:
            payload = _serialize(event)

            action = str(payload.get("action", "unknown")).lower()
            status = str(payload.get("status", "pending")).lower()

            # Rename action_id -> id so the backend/frontend can use a single key
            payload["id"] = str(payload.pop("action_id", payload.get("id", "")))

            # Enrich with display fields
            payload["action"] = action
            payload["action_label"] = ACTION_LABELS.get(
                action, action.replace("_", " ").title()
            )
            payload["status"] = status
            payload["timestamp"] = _as_iso(event.timestamp)

            # Routing / identity fields the frontend table expects
            payload["source"] = self._endpoint_id
            payload["endpoint"] = self._endpoint_id

            # Normalise the rest
            payload["target"] = str(payload.get("target", "") or "")
            payload["target_type"] = str(payload.get("target_type", "unknown") or "unknown")
            payload["details"] = str(payload.get("details", "") or "")
            payload["reason"] = str(payload.get("reason", "") or "")
            payload["agent"] = str(payload.get("agent_name", "") or "")
            payload["severity"] = str(payload.get("severity", "medium")).lower()
            payload["triggered_by"] = str(payload.get("triggered_by", "") or "")
            payload["error"] = payload.get("error") or None
            payload["success"] = bool(payload.get("success", status != "failed"))

            # Containment flag — drives the frontend filter chips
            payload["containment"] = action in CONTAINMENT_ACTIONS

            if not isinstance(payload.get("metadata"), dict):
                payload["metadata"] = {}

            # Forward to POST /api/agent/actions
            await self._queue.add_to_endpoint("actions", payload)

            log.info(
                "Action forwarded: %s -> %s [%s]",
                action,
                payload["target"] or "-",
                status,
            )

            # (Pseudo-lock rows come from PseudoLockUpdate, not from here.)

        except Exception as exc:  # never let a bridge failure kill the engine
            log.exception("Failed to forward ActionRecord: %s", exc)