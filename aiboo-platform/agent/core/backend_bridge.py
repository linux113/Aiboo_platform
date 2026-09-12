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
from .events import AgentFinding, CorrelatedAlert, GateDecision, ResponseAction
from .config import config
from .alert_queue import OfflineQueueManager

log = logging.getLogger("DashboardBridge")


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
        log.info("DashboardBridge subscribed to AgentFinding, CorrelatedAlert, GateDecision")

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

    # ---- Event handlers ----

    async def _on_finding(self, event: AgentFinding) -> None:
        """Queue a finding (only high/critical)."""
        if event.severity.value not in ("high", "critical"):
            return

        payload = _serialize(event)
        # Normalise fields for the backend
        payload.pop("timestamp", None)
        payload["id"] = payload.pop("event_id", "")
        payload["timestamp"] = (
            event.timestamp.isoformat()
            if isinstance(event.timestamp, datetime)
            else str(event.timestamp)
        )
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        payload["source"] = self._endpoint_id

        await self._queue.add_to_endpoint("findings", payload)

        # Also handle pseudo‑lock if action includes it
        is_pseudo_lock = (
            any(a == ResponseAction.PSEUDO_LOCK for a in event.actions)
            or "lock_id" in event.metadata
        )
        if is_pseudo_lock:
            lock_payload = {
                "lock_id": event.metadata.get("lock_id", f"lock_{event.event_id}"),
                "event_id": event.event_id,
                "agent": event.agent_name,
                "severity": event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
                "summary": event.summary,
                "active": True,
                "locked_at": (
                    event.timestamp.isoformat()
                    if isinstance(event.timestamp, datetime)
                    else str(event.timestamp)
                ),
                "source": self._endpoint_id,
            }
            await self._queue.add_to_endpoint("pseudo-lock", lock_payload)

    async def _on_correlated(self, event: CorrelatedAlert) -> None:
        payload = _serialize(event)
        payload["alert_id"] = str(payload.get("alert_id", ""))
        payload["timestamp"] = event.timestamp.isoformat()
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        payload["description"] = payload.get("description") or payload.get("summary", "")
        await self._queue.add_to_endpoint("correlated", payload)

    async def _on_gate_decision(self, event: GateDecision) -> None:
        payload = _serialize(event)
        payload["gate"] = int(payload.get("gate", 0))
        payload["gate_label"] = {
            1: "Perimeter",
            2: "Behavioural",
            3: "Adaptive Response",
        }.get(payload["gate"], "Unknown")
        payload["timestamp"] = event.timestamp.isoformat()
        payload["confidence"] = float(payload.get("confidence", 0))
        if isinstance(payload.get("severity"), str):
            payload["severity"] = payload["severity"].lower()
        await self._queue.add_to_endpoint("gate-decision", payload)