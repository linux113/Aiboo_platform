"""
command_channel.py — Persistent Socket.IO connection to the backend
so the dashboard can dispatch remote actions to this endpoint.

Flow:
    Dashboard  --POST /api/agent/commands-->  Backend
    Backend    --"command" on /agent-channel-->  THIS CLIENT
    THIS CLIENT --> RealResponseEngine.execute_remote_action()
    THIS CLIENT --"agent:command-ack" (received / executed / failed)--> Backend

The resulting ActionRecord is published on the EventBus and forwarded to
POST /api/agent/actions by DashboardBridge, so the "Isolation & Termination"
tab shows the row exactly like a locally-triggered action.

NOTE on namespaces: python-socketio ignores the path part of the URL.
The namespace must be passed explicitly (namespaces=[NAMESPACE]) and every
handler / emit must use it. Connecting to the default "/" namespace fails,
because the backend protects "/" with dashboard JWT auth.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Awaitable, Callable, Dict, Optional, TYPE_CHECKING

import socketio

if TYPE_CHECKING:
    from response.real_response_engine import RealResponseEngine

log = logging.getLogger("CommandChannel")

NAMESPACE = "/agent-channel"


class CommandChannel:
    """
    Connects to the backend over Socket.IO, registers this endpoint,
    and executes remote commands pushed by the dashboard.
    """

    def __init__(
        self,
        engine: "RealResponseEngine",
        backend_url: str,
        api_key: str,
        endpoint_id: Optional[str] = None,
        allowed_actions: Optional[set] = None,
        local_handlers: Optional[Dict[str, Callable[[str, dict], Awaitable[Optional[dict]]]]] = None,
    ) -> None:
        self._engine = engine
        # Commands handled by agent components directly instead of the
        # response engine, e.g. "restore_pseudo_lock" -> PseudoLockAgent,
        # "inject_test_event" -> publish a test ThreatEvent on the bus.
        # handler(target, params) may return a small dict sent back in the ack.
        self._local_handlers = dict(local_handlers or {})
        self._backend_url = (backend_url or "").rstrip("/")
        self._api_key = api_key
        self._endpoint_id = endpoint_id or socket.gethostname()
        # None = allow every action the engine knows about
        self._allowed_actions = allowed_actions

        self._sio = socketio.AsyncClient(
            reconnection=True,
            reconnection_attempts=0,       # retry forever after first connect
            reconnection_delay=2,
            reconnection_delay_max=30,
            logger=False,
            engineio_logger=False,
        )
        self._task: Optional[asyncio.Task] = None
        self._stopping = False
        self._register_handlers()

    # ------------------------------------------------------------------
    # Socket.IO handlers (all bound to the /agent-channel namespace)
    # ------------------------------------------------------------------
    def _register_handlers(self) -> None:
        async def on_connect():
            log.info(
                "Command channel CONNECTED to %s%s as endpoint '%s' "
                "- remote actions from the dashboard are now enabled",
                self._backend_url, NAMESPACE, self._endpoint_id,
            )
            await self._sio.emit(
                "agent:register",
                {"endpoint_id": self._endpoint_id, "hostname": socket.gethostname()},
                namespace=NAMESPACE,
            )

        async def on_disconnect(*_args):
            if not self._stopping:
                log.warning("Command channel disconnected - will reconnect automatically")

        async def on_connect_error(data=None):
            log.warning("Command channel connect error: %s", data)

        async def on_command(data):
            # Run each command in its own task so a slow action (e.g. a
            # process that ignores SIGTERM) never blocks the socket loop.
            asyncio.create_task(self._handle_command(data or {}))

        self._sio.on("connect", on_connect, namespace=NAMESPACE)
        self._sio.on("disconnect", on_disconnect, namespace=NAMESPACE)
        self._sio.on("connect_error", on_connect_error, namespace=NAMESPACE)
        self._sio.on("command", on_command, namespace=NAMESPACE)

    async def _ack(self, cmd_id, status: str, error: Optional[str] = None,
                   result: Optional[dict] = None) -> None:
        payload = {"cmd_id": cmd_id, "endpoint_id": self._endpoint_id, "status": status}
        if error:
            payload["error"] = error
        if result:
            payload["result"] = result
        try:
            await self._sio.emit("agent:command-ack", payload, namespace=NAMESPACE)
        except Exception as exc:  # socket may have dropped mid-command
            log.warning("Could not send ack %s for %s: %s", status, cmd_id, exc)

    async def _handle_command(self, data: dict) -> None:
        cmd_id = data.get("cmd_id")
        action = str(data.get("action") or "").strip()
        target = str(data.get("target") or "").strip()
        params = data.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        log.warning("REMOTE COMMAND received: %s -> %s (cmd %s)", action, target or "-", cmd_id)

        # ACK receipt immediately so the dashboard shows "received"
        await self._ack(cmd_id, "received")

        if (self._allowed_actions is not None and action not in self._allowed_actions
                and action not in self._local_handlers):
            err = f"Action '{action}' is not allowed on this endpoint"
            log.warning("Remote command rejected: %s", err)
            await self._ack(cmd_id, "failed", err)
            return

        try:
            params = {**params, "cmd_id": cmd_id}
            local = self._local_handlers.get(action)
            if local is not None:
                result = await local(target, params)
                await self._ack(cmd_id, "executed",
                                result=result if isinstance(result, dict) else None)
                return
            await self._engine.execute_remote_action(action, target, params)
            await self._ack(cmd_id, "executed")
        except Exception as exc:
            log.error("Remote command %s failed: %s", cmd_id, exc)
            await self._ack(cmd_id, "failed", str(exc))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def _connect_loop(self) -> None:
        """
        Keep trying the FIRST connection until it succeeds. (python-socketio
        only auto-reconnects after an initial successful connect, so if the
        backend is down when the agent starts we must retry ourselves.)
        """
        delay = 2
        while not self._stopping and not self._sio.connected:
            try:
                await self._sio.connect(
                    self._backend_url,
                    namespaces=[NAMESPACE],
                    auth={
                        "api_key": self._api_key,
                        "endpoint_id": self._endpoint_id,
                        "hostname": socket.gethostname(),
                    },
                    # Skip ngrok's free-tier browser interstitial, if used
                    headers={"ngrok-skip-browser-warning": "true"},
                    transports=["websocket", "polling"],
                    wait_timeout=10,
                )
                return
            except Exception as exc:
                log.warning(
                    "Command channel could not connect to %s (%s) - retrying in %ss",
                    self._backend_url, exc, delay,
                )
                try:
                    await self._sio.disconnect()
                except Exception:
                    pass
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    def start(self) -> None:
        """Start connecting in the background (non-blocking)."""
        if not self._backend_url:
            log.warning("Command channel disabled: no backend URL configured")
            return
        log.info("Connecting command channel to %s (namespace %s)", self._backend_url, NAMESPACE)
        self._stopping = False
        self._task = asyncio.create_task(self._connect_loop())

    @property
    def connected(self) -> bool:
        return self._sio.connected

    async def stop(self) -> None:
        self._stopping = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await self._sio.disconnect()
        except Exception:
            pass
        log.info("Command channel stopped")
