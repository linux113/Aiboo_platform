"""
command_dashboard.py — AiBoO Command Dashboard
 
Subscribes to AgentFindings and CorrelatedAlerts and renders them
to the terminal in a structured, human-readable format.
 
In a production deployment this module would push events to a
WebSocket stream feeding a React/Next.js front-end.
"""
 
from __future__ import annotations
 
import logging
 
from core.event_bus import EventBus
from core.events import AgentFinding, CorrelatedAlert, Severity
 
log = logging.getLogger("Dashboard")
 
# ANSI colour codes
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_WHITE  = "\033[97m"
_DIM    = "\033[2m"
 
_SEV_COLOR = {
    Severity.LOW:      _GREEN,
    Severity.MEDIUM:   _YELLOW,
    Severity.HIGH:     "\033[33m",
    Severity.CRITICAL: _RED,
}
 
 
def _sev_badge(sev: Severity) -> str:
    col = _SEV_COLOR.get(sev, _WHITE)
    return f"{_BOLD}{col}[{sev.value.upper()}]{_RESET}"
 
 
class CommandDashboard:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
 
    def start(self) -> None:
        self.bus.subscribe(AgentFinding,    self._on_finding)
        self.bus.subscribe(CorrelatedAlert, self._on_correlated)
        log.info("Dashboard active.")
 
    async def _on_finding(self, finding: AgentFinding) -> None:
        sev  = _sev_badge(finding.severity)
        conf = f"{finding.confidence * 100:.0f}%"
        acts = ", ".join(a.value for a in finding.actions)
 
        print(
            f"\n{_DIM}{'─'*62}{_RESET}\n"
            f"  {_BOLD}{_CYAN}AGENT FINDING{_RESET}  "
            f"{sev}  conf={_BOLD}{conf}{_RESET}\n"
            f"  {_DIM}agent   :{_RESET} {finding.agent_name}\n"
            f"  {_DIM}event   :{_RESET} [{finding.event_id}] "
            f"{finding.threat_type.value}\n"
            f"  {_DIM}summary :{_RESET} {finding.summary}\n"
            f"  {_DIM}actions :{_RESET} {acts}"
        )
 
    async def _on_correlated(self, alert: CorrelatedAlert) -> None:
        sev  = _sev_badge(alert.severity)
        conf = f"{alert.confidence * 100:.0f}%"
        acts = ", ".join(a.value for a in alert.actions)
 
        print(
            f"\n{'═'*62}\n"
            f"  {_BOLD}{_RED}⚑  CORRELATED ALERT  ⚑{_RESET}  "
            f"{sev}  conf={_BOLD}{conf}{_RESET}\n"
            f"  {_DIM}alert_id:{_RESET} {alert.alert_id}\n"
            f"  {_DIM}detail  :{_RESET} {alert.description}\n"
            f"  {_DIM}actions :{_RESET} {acts}\n"
            f"{'═'*62}"
        )