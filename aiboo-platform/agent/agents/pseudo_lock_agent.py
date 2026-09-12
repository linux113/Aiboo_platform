"""
agents/pseudo_lock_agent.py — Pseudo-Lock Defense Agent
 
AiBoO's core dynamic isolation mechanism.
 
When a finding demands PSEUDO_LOCK, this agent:
  1. Dynamically remaps the targeted endpoint / port to a decoy address.
  2. Records the original binding for later restoration.
  3. Emits a secondary AgentFinding confirming the lock was applied.
 
The "shift" is simulated here; in production it would invoke an SDN
controller, iptables/nftables, or a cloud security group API.
"""
 
from __future__ import annotations
 
import asyncio
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
 
from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType, PseudoLockRestoreRequest,
)
 
 
@dataclass
class LockRecord:
    original_endpoint: str
    decoy_endpoint:    str
    locked_at:         datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    restored:          bool     = False
 
 
def _random_decoy_port() -> int:
    """Pick a random high port in the ephemeral range."""
    return random.randint(32768, 60999)
 
 
def _random_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
 
 
class PseudoLockAgent(BaseAgent):
    """
    Subscribes to AgentFindings (not raw ThreatEvents) so it fires
    only after a specialist agent has already confirmed a threat.
    """
 
    def __init__(self, bus: EventBus) -> None:
        super().__init__("PseudoLockAgent", bus)
        self._lock_registry: dict[str, LockRecord] = {}
 
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
 
    async def _handle_finding(self, finding: AgentFinding) -> None:
        if ResponseAction.PSEUDO_LOCK not in finding.actions:
            return
 
        self.log.info(
            "PSEUDO_LOCK triggered for event [%s] from %s (sev=%s)",
            finding.event_id, finding.agent_name, finding.severity.value,
        )
        await self._apply_pseudo_lock(finding)
 
    async def _apply_pseudo_lock(self, finding: AgentFinding) -> None:
        # Simulate the async SDN / firewall rule update
        await asyncio.sleep(0.10)
 
        meta         = finding.metadata.get("raw_payload", {})
        orig_port    = meta.get("dst_port", "unknown")
        src_ip       = meta.get("src_ip", meta.get("user_id", "unknown"))
        orig_ep      = f"{src_ip}:{orig_port}"
        decoy_port   = _random_decoy_port()
        decoy_ep     = f"decoy-{_random_token()}.internal:{decoy_port}"
 
        record = LockRecord(original_endpoint=orig_ep, decoy_endpoint=decoy_ep)
        lock_id = f"lock_{finding.event_id}"
        self._lock_registry[lock_id] = record
 
        self.log.warning(
            "⚑  PSEUDO_LOCK applied — original=%s → decoy=%s  [lock_id=%s]",
            orig_ep, decoy_ep, lock_id,
        )
 
        # Publish a follow-up finding so the orchestrator sees the action taken
        confirmation = AgentFinding(
            agent_name  = self.name,
            event_id    = finding.event_id,
            threat_type = finding.threat_type,
            severity    = finding.severity,
            confidence  = 1.0,
            summary     = (
                f"Pseudo-Lock applied. Endpoint {orig_ep} remapped to "
                f"decoy {decoy_ep}. Attacker traffic now routed to honeypot."
            ),
            actions     = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD],
            metadata    = {
                "lock_id":           lock_id,
                "original_endpoint": orig_ep,
                "decoy_endpoint":    decoy_ep,
            },
        )
        await self.bus.publish(confirmation)
 
    def active_locks(self) -> list[LockRecord]:
        return [r for r in self._lock_registry.values() if not r.restored]
 
    async def _handle_restore_request(self, req: PseudoLockRestoreRequest) -> None:
        result = await self.restore(req.lock_id)
        if result:
            self.log.info("Restored lock %s via dashboard request.", req.lock_id)
        else:
            self.log.warning("Restore request for lock %s failed — not found or already restored.", req.lock_id)

    async def restore(self, lock_id: str) -> bool:
        """Restore the original endpoint mapping after threat is neutralised."""
        await asyncio.sleep(0.05)
        record = self._lock_registry.get(lock_id)
        if not record or record.restored:
            return False
        record.restored = True
        self.log.info("Endpoint %s restored from decoy %s.",
                      record.original_endpoint, record.decoy_endpoint)
        return True
 