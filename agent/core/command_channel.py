"""
command_channel.py — Persistent WebSocket connection to the backend
so the dashboard can dispatch remote actions to this endpoint.
"""
from __future__ import annotations
import asyncio
import logging
import socket
from typing import Optional, TYPE_CHECKING

import socketio

if TYPE_CHECKING:
    from ..response.real_response_engine import RealResponseEngine

log = logging.getLogger("CommandChannel")


class CommandChannel:
    """
    Connects to the backend over Socket.IO, registers this endpoint,
    and executes remote commands pushed by the dashboard.

    Commands are dispatched to RealResponseEngine.execute_remote_action(),
    which publishes ActionRecords that DashboardBridge forwards back to the
    backend — so the Isolation & Termination tab lights up identically to
    a locally-triggered action.
    """

    def __init__(
        self,
        engine: "RealResponseEngine",
        backend_url: str,
        api_key: str,
        endpoint_id: Optional[str] = None,
    ) -> None:
        self._engine = engine
        self._backend_url = backend_url.rstrip("/")
        self._api_key = api_key
        self._endpoint_id = endpoint_id or socket.gethostname()

        self._sio = socketio.AsyncClient(
            reconnection=True,
            reconnection_attempts=0,       # retry forever
            reconnection_delay=2,
            reconnection_delay_max=30,
            logger=False,
            engineio_logger=False,
        )
        self._register_handlers()

    def _register_handlers(self) -> None:
        @self._sio.event
        async def connect():
            log.info("Command channel connected to %s", self._backend_url)
            await self._sio.emit("agent:register", {
                "endpoint_id": self._endpoint_id,
                "hostname": socket.gethostname(),
            })

        @self._sio.event
        async def disconnect():
            log.warning("Command channel disconnected — will retry")

        @self._sio.on("command")
        async def on_command(data: dict):
            await self._handle_command(data)

    async def _handle_command(self, data: dict) -> None:
        cmd_id = data.get("cmd_id")
        action = data.get("action")
        target = data.get("target", "")
        params = data.get("params", {}) or {}

        log.warning(
            "REMOTE COMMAND received: %s → %s (cmd %s)",
            action, target, cmd_id,
        )

        # ACK receipt immediately so the dashboard shows "in flight"
        await self._sio.emit("agent:command-ack", {
            "cmd_id": cmd_id,
            "endpoint_id": self._endpoint_id,
            "status": "received",
        })

        try:
            await self._engine.execute_remote_action(action, target, params)
            await self._sio.emit("agent:command-ack", {
                "cmd_id": cmd_id,
                "endpoint_id": self._endpoint_id,
                "status": "executed",
            })
        except Exception as exc:
            log.exception("Remote command failed: %s", exc)
            await self._sio.emit("agent:command-ack", {
                "cmd_id": cmd_id,
                "endpoint_id": self._endpoint_id,
                "status": "failed",
                "error": str(exc),
            })

    async def start(self) -> None:
        url = f"{self._backend_url}/agent-channel"
        log.info("Connecting command channel to %s", url)
        await self._sio.connect(
            url,
            auth={"api_key": self._api_key, "endpoint_id": self._endpoint_id},
            transports=["websocket"],
        )

    async def stop(self) -> None:
        if self._sio.connected:
            await self._sio.disconnect()