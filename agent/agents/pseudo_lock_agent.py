"""
agents/pseudo_lock_agent.py — Pseudo-Lock Defense Agent

AiBoO's dynamic isolation mechanism.

When a finding demands PSEUDO_LOCK, this agent:
  1. Opens a REAL listening socket on a decoy port (0.0.0.0).
  2. Logs every connection the decoy receives (attacker IP + payload).
  3. Records the original binding for later restoration.
  4. Emits a secondary AgentFinding confirming the lock was applied.

The decoy is a genuine TCP listener — `netstat` will show it, and a
live `telnet` test will hit it. Restore closes the socket.
"""

from __future__ import annotations

import asyncio
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType, PseudoLockRestoreRequest, PseudoLockUpdate,
)


@dataclass
class LockRecord:
    original_endpoint: str
    decoy_endpoint:    str
    decoy_port:        int
    locked_at:         datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    restored:          bool     = False
    hits:              int      = 0


def _random_decoy_port() -> int:
    """Pick a random high port in the ephemeral range."""
    return random.randint(32768, 60999)


def _random_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# A fake banner sent to anything that connects — makes the decoy look
# like a real service so attackers stay on the line long enough to be logged.
_FAKE_BANNERS = [
    b"SSH-2.0-OpenSSH_8.0\r\n",
    b"220 FTP server ready.\r\n",
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    b"220 SMTP Server Ready\r\n",
]


class PseudoLockAgent(BaseAgent):
    """
    Subscribes to AgentFindings (not raw ThreatEvents) so it fires
    only after a specialist agent has already confirmed a threat.

    When a finding requests PSEUDO_LOCK, this agent opens a real TCP
    listener on a random high port. The port is bound via asyncio's
    start_server, so it's visible in `netstat` and reachable over the
    network. Every connection is logged with the peer's IP and any
    bytes they send.
    """

    def __init__(self, bus: EventBus) -> None:
        super().__init__("PseudoLockAgent", bus)
        self._lock_registry: dict[str, LockRecord] = {}
        self._decoy_servers: dict[str, asyncio.AbstractServer] = {}

    def register(self) -> None:
        # Override: subscribe to AgentFinding, not ThreatEvent
        self.bus.subscribe(AgentFinding, self._handle_finding)
        self.bus.subscribe(PseudoLockRestoreRequest, self._handle_restore_request)
        self.log.info("Registered — monitoring AgentFindings + PseudoLockRestoreRequest.")

    def can_handle(self, event: ThreatEvent) -> bool:
        # Not used directly (we subscribe to AgentFinding instead)
        return False

    async def analyse(self, event: ThreatEvent) -> AgentFinding | None:
        return None

    # ============================================================
    # Event handlers
    # ============================================================

    async def _handle_finding(self, finding: AgentFinding) -> None:
        if ResponseAction.PSEUDO_LOCK not in finding.actions:
            return

        self.log.info(
            "PSEUDO_LOCK triggered for event [%s] from %s (sev=%s)",
            finding.event_id, finding.agent_name, finding.severity.value,
        )
        try:
            await self.open_lock(f"lock_{finding.event_id}", finding)
        except Exception as exc:
            self.log.error(
                "Failed to apply pseudo-lock for event [%s]: %s",
                finding.event_id, exc,
            )

    # ============================================================
    # Core: open a REAL decoy listener
    # ============================================================

    async def _apply_pseudo_lock(self, finding: AgentFinding) -> None:
        """Backwards-compatible wrapper."""
        await self.open_lock(f"lock_{finding.event_id}", finding)

    @staticmethod
    def _original_endpoint(event) -> str:
        meta = getattr(event, "metadata", None) or {}
        raw = meta.get("raw_payload") or {}
        payload = meta.get("payload") or {}
        if not raw and isinstance(payload, dict):
            raw = payload.get("raw_payload") or payload
        src = (raw.get("src_ip") or raw.get("target") or raw.get("user_id")
               or meta.get("target") or "unknown")
        port = raw.get("dst_port", "unknown")
        return f"{src}:{port}"

    async def open_lock(self, lock_id: str, event=None) -> LockRecord:
        """
        Bind a real TCP listener on a random high port for ``lock_id``.

        The decoy accepts any connection, sends a fake service banner,
        reads up to 1 KB of client data, and logs everything. This is a
        genuine honeypot — `netstat` shows the listener and a live
        `telnet <agent-ip> <port>` will connect.

        If the lock is already active (several agents flagged the same
        event) the existing decoy is returned — no second socket is opened,
        so every open port can always be closed again by Restore.
        """
        existing = self._lock_registry.get(lock_id)
        if existing and not existing.restored and lock_id in self._decoy_servers:
            return existing

        decoy_port = _random_decoy_port()
        server: Optional[asyncio.AbstractServer] = None

        # Retry on port collisions (up to 5 attempts)
        for attempt in range(5):
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=decoy_port: self._handle_decoy_connection(r, w, p),
                    host="0.0.0.0",
                    port=decoy_port,
                )
                break
            except OSError as exc:
                self.log.debug(
                    "Decoy bind failed on port %s (attempt %d): %s",
                    decoy_port, attempt + 1, exc,
                )
                decoy_port = _random_decoy_port()
                server = None

        if server is None:
            raise RuntimeError(
                "Could not bind any decoy port after 5 attempts — "
                "all candidate ports were in use"
            )

        orig_ep = self._original_endpoint(event) if event is not None else "unknown"
        decoy_ep = f"0.0.0.0:{decoy_port}"

        record = LockRecord(
            original_endpoint=orig_ep,
            decoy_endpoint=decoy_ep,
            decoy_port=decoy_port,
        )
        self._lock_registry[lock_id] = record
        self._decoy_servers[lock_id] = server

        self.log.warning(
            "PSEUDO_LOCK applied — REAL decoy listening on 0.0.0.0:%s  "
            "[lock_id=%s, original=%s]",
            decoy_port, lock_id, orig_ep,
        )

        severity = getattr(event, "severity", Severity.HIGH)
        await self.bus.publish(PseudoLockUpdate(
            lock_id=lock_id,
            active=True,
            event_id=str(getattr(event, "event_id", "") or ""),
            agent=str(getattr(event, "agent_name", "") or self.name),
            severity=severity.value if hasattr(severity, "value") else str(severity),
            summary=(
                f"Decoy listening on 0.0.0.0:{decoy_port} for "
                f"{orig_ep[:-8] if str(orig_ep).endswith(':unknown') else orig_ep}. "
                f"Restore closes it."
            ),
            decoy_port=decoy_port,
            decoy_endpoint=decoy_ep,
            original_endpoint=orig_ep,
        ))
        return record

    # ============================================================
    # Decoy connection handler
    # ============================================================

    async def _handle_decoy_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        decoy_port: int,
    ) -> None:
        """
        Called for every TCP connection the decoy receives.

        Sends a fake service banner, reads up to 1 KB from the client,
        logs the peer IP and payload, then closes.
        """
        peer = writer.get_extra_info("peername")
        self.log.warning("DECOY HIT from %s on port %s", peer, decoy_port)

        # Increment hit counter on the matching record
        for rec in self._lock_registry.values():
            if rec.decoy_port == decoy_port and not rec.restored:
                rec.hits += 1
                break

        # Send a fake banner so the attacker thinks it's a real service
        try:
            banner = random.choice(_FAKE_BANNERS)
            writer.write(banner)
            await writer.drain()
        except Exception as exc:
            self.log.debug("Decoy banner write failed: %s", exc)

        # Capture what they send (up to 1 KB, 10s timeout)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            if data:
                self.log.warning(
                    "DECOY DATA from %s (%d bytes): %r",
                    peer, len(data), data[:200],
                )
            else:
                self.log.info("Decoy connection from %s closed with no data", peer)
        except asyncio.TimeoutError:
            self.log.info("Decoy connection from %s timed out (no data)", peer)
        except Exception as exc:
            self.log.debug("Decoy read error from %s: %s", peer, exc)

        # Close cleanly
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # ============================================================
    # Public API
    # ============================================================

    def active_locks(self) -> list[LockRecord]:
        return [r for r in self._lock_registry.values() if not r.restored]

    async def _handle_restore_request(self, req: PseudoLockRestoreRequest) -> None:
        result = await self.restore(req.lock_id)
        if result:
            self.log.info("Restored lock %s via dashboard request.", req.lock_id)
        else:
            self.log.warning(
                "Restore request for lock %s failed — not found or already restored.",
                req.lock_id,
            )

    async def remote_restore(self, target: str, params: Optional[dict] = None) -> dict:
        """
        Called by the CommandChannel when the dashboard presses Restore.

        Closes the decoy if it is open. If this agent has no such open
        decoy (already closed, or the agent was restarted — restarts close
        every decoy), the dashboard is told so and the lock is cleared.
        """
        lock_id = str(target or "").strip()
        if not lock_id:
            raise RuntimeError("restore_pseudo_lock needs a lock id")
        record = self._lock_registry.get(lock_id)
        if record and not record.restored:
            port = record.decoy_port
            await self.restore(lock_id)
            return {"lock_id": lock_id, "closed": True, "decoy_port": port,
                    "message": f"Decoy port {port} closed"}

        message = ("No open decoy for this lock on this PC "
                   "(already closed, or the agent restarted — restarts close all decoys)")
        self.log.info("Restore %s: %s", lock_id, message)
        await self.bus.publish(PseudoLockUpdate(lock_id=lock_id, active=False, message=message))
        return {"lock_id": lock_id, "closed": False, "message": message}

    async def restore(self, lock_id: str) -> bool:
        """
        Close the decoy listener and mark the record as restored.

        After this returns, `netstat` will no longer show the port and
        any further connections will be refused at the TCP layer.
        """
        record = self._lock_registry.get(lock_id)
        if not record or record.restored:
            return False

        server = self._decoy_servers.pop(lock_id, None)
        if server:
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=5)
            except Exception as exc:
                self.log.debug("Error closing decoy server for %s: %s", lock_id, exc)

        record.restored = True
        self.log.info(
            "Endpoint %s restored. Decoy on %s closed. (Total hits: %d)",
            record.original_endpoint, record.decoy_endpoint, record.hits,
        )
        await self.bus.publish(PseudoLockUpdate(
            lock_id=lock_id,
            active=False,
            decoy_port=record.decoy_port,
            decoy_endpoint=record.decoy_endpoint,
            original_endpoint=record.original_endpoint,
            hits=record.hits,
            message=f"Decoy port {record.decoy_port} closed",
        ))
        return True

    # ============================================================
    # Shutdown
    # ============================================================

    async def stop(self) -> None:
        """Close all active decoy servers on shutdown."""
        for lock_id, server in list(self._decoy_servers.items()):
            try:
                server.close()
                await server.wait_closed()
            except Exception:
                pass
            self._decoy_servers.pop(lock_id, None)
        self.log.info("PseudoLockAgent stopped — all decoys closed.")