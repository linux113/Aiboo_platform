"""
gates/gate_response_bridge.py — Gate Decision → Response Bridge
 
Subscribes to Gate 3 GateDecisions and executes all ResponseActions,
bridging the tri-gate pipeline into the existing AutonomousResponseEngine
pattern. Also feeds confirmed threats into the CommandDashboard.
"""
 
from __future__ import annotations
 
import asyncio
import logging
 
from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, ResponseAction, Severity
 
log = logging.getLogger("GateResponseBridge")
 
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_DIM    = "\033[2m"
 
_SEV_COLOR = {
    Severity.LOW:      _GREEN,
    Severity.MEDIUM:   _YELLOW,
    Severity.HIGH:     "\033[33m",
    Severity.CRITICAL: _RED,
}
 
 
class GateResponseBridge:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._action_handlers = {
            ResponseAction.ISOLATE_ASSET:   self._isolate,
            ResponseAction.PSEUDO_LOCK:     self._pseudo_lock,
            ResponseAction.REVOKE_IDENTITY: self._revoke,
            ResponseAction.LOCK_ZONE:       self._lock_zone,
            ResponseAction.NOTIFY_SECURITY: self._notify,
            ResponseAction.ESCALATE_SOC:    self._escalate,
        }
 
    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._on_decision)
        log.info("Gate Response Bridge — ACTIVE")
 
    async def _on_decision(self, d: GateDecision) -> None:
        # Print ALL gate decisions to dashboard
        self._render(d)
 
        # Only execute actions on Gate 3 final decisions
        if d.gate != GateLevel.GATE_3 or d.verdict != GateVerdict.BLOCK:
            return
 
        log.warning(
            "Executing %d response actions for Gate 3 decision [%s]",
            len(d.actions), d.event_id,
        )
        await asyncio.gather(*(
            handler(d)
            for action, handler in self._action_handlers.items()
            if action in d.actions
        ))
 
    def _render(self, d: GateDecision) -> None:
        col  = _SEV_COLOR.get(d.severity, "\033[97m")
        sev  = f"{_BOLD}{col}[{d.severity.value.upper()}]{_RESET}"
        gate = f"Gate {d.gate.value} — {d.gate.label()}"
 
        verdict_color = {
            GateVerdict.PASS:     _GREEN,
            GateVerdict.HOLD:     _YELLOW,
            GateVerdict.BLOCK:    "\033[33m",
            GateVerdict.ESCALATE: _RED,
        }.get(d.verdict, "\033[97m")
 
        verdict_str = f"{_BOLD}{verdict_color}{d.verdict.value.upper()}{_RESET}"
 
        log.info(
            f"\n{_DIM}{'─'*62}{_RESET}\n"
            f"  {_BOLD}{_CYAN}{gate}{_RESET}  {sev}  {verdict_str}  "
            f"conf={_BOLD}{d.confidence*100:.0f}%{_RESET}\n"
            f"  {_DIM}event  :{_RESET} [{d.event_id}] {d.threat_type.value}\n"
            f"  {_DIM}reason :{_RESET} {d.reason}\n"
            f"  {_DIM}actions:{_RESET} {', '.join(a.value for a in d.actions)}"
        )
 
        if d.gate == GateLevel.GATE_3:
            log.warning("GATE 3 FINAL — RESPONSE EXECUTING for event %s", d.event_id)
 
    # ── Action handlers ───────────────────────────────────────────
 
    async def _isolate(self, d: GateDecision) -> None:
        await asyncio.sleep(0.03)
        log.warning("[ACTION] Asset isolation — event %s", d.event_id)
 
    async def _pseudo_lock(self, d: GateDecision) -> None:
        await asyncio.sleep(0.03)
        decoy = d.metadata.get("decoy", "decoy.internal:?")
        entity = d.metadata.get("entity", "unknown")
        log.warning(
            "[ACTION] Pseudo-Lock applied — entity=%r remapped → %s",
            entity, decoy,
        )
 
    async def _revoke(self, d: GateDecision) -> None:
        await asyncio.sleep(0.03)
        entity = d.metadata.get("entity", "unknown")
        log.warning("[ACTION] Identity revoked — %r", entity)
 
    async def _lock_zone(self, d: GateDecision) -> None:
        await asyncio.sleep(0.03)
        zone = d.metadata.get("payload", {}).get("zone", "unknown")
        log.warning("[ACTION] Zone locked — %r", zone)
 
    async def _notify(self, d: GateDecision) -> None:
        await asyncio.sleep(0.02)
        log.warning("[ACTION] Security team notified — event %s", d.event_id)
 
    async def _escalate(self, d: GateDecision) -> None:
        await asyncio.sleep(0.02)
        log.critical(
            "[ACTION] SOC escalation — event %s sev=%s",
            d.event_id, d.severity.value,
        )