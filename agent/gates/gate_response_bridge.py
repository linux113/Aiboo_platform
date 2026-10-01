"""
gates/gate_response_bridge.py - prints TriGate decisions in the agent window.

Gate 1 / Gate 2 decisions are intermediate (logged at DEBUG); the final
Gate 3 decision is printed as a short block with the three scores and the
recommended actions.

Nothing is executed here. (The old bridge printed "[ACTION] Identity
revoked" etc. although nothing happened.) Real actions run only in
RealResponseEngine when auto_response = true, or when you click an action
in the dashboard.
"""

from __future__ import annotations

import logging

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, Severity

log = logging.getLogger("TriGate")

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_CYAN = "\033[96m"
_COLOR = {
    Severity.LOW: "\033[92m",
    Severity.MEDIUM: "\033[93m",
    Severity.HIGH: "\033[33m",
    Severity.CRITICAL: "\033[91m",
}


class GateResponseBridge:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._on_decision)
        log.info("TriGate console view active (Trust -> Intent -> Impact)")

    async def _on_decision(self, d: GateDecision) -> None:
        if d.gate != GateLevel.GATE_3:
            log.debug("Gate %d (%s): %s", d.gate.value, d.gate.label(), d.reason)
            return
        self._render(d)

    def _render(self, d: GateDecision) -> None:
        tri = (d.metadata or {}).get("trigate") or {}
        col = _COLOR.get(d.severity, "")
        lines = [
            f"{_DIM}{'-' * 62}{_RESET}",
            f"  {_BOLD}{_CYAN}TRIGATE{_RESET}  {_BOLD}{col}{d.verdict.value.upper()} "
            f"[{d.severity.value.upper()}]{_RESET}  event {d.event_id}",
            f"  {d.reason}",
        ]
        for key, name in (("trust", "Trust "), ("intent", "Intent"), ("impact", "Impact")):
            g = tri.get(key) or {}
            if not g:
                continue
            reasons = "; ".join(f"{x['text']} ({x['points']:+d})" for x in g.get("factors", [])[:4])
            lines.append(f"  {_DIM}{name} {g.get('score', '?'):>3}:{_RESET} {reasons}")
        recs = [r["text"] for r in tri.get("recommended", []) if r.get("action") != "log"]
        if recs:
            lines.append(f"  {_DIM}Recommended:{_RESET} " + " | ".join(recs))
        text = "\n".join(lines)
        if d.verdict == GateVerdict.PASS:
            log.info(text)
        else:
            log.warning(text)
