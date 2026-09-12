"""
response/isolation_advisor.py — Isolation Advisor

Turns high/critical AgentFindings into ACTIONABLE isolation suggestions
and lets an operator execute or dismiss them (dashboard Isolation tab).

Flow:
  AgentFinding (high/critical) ──► IsolationAdvisor
        ├─ LLM advice (if ANTHROPIC_API_KEY set) or offline heuristic advice
        ├─ Suggestion stored: {id, target, actions, advice, status=pending}
        ├─ Optional AUTO mode: execute immediately on critical+high-confidence
        └─ Execution: pseudo_lock → PseudoLockAgent via bus · kill_process → psutil
                       isolate_host → executor firewall rules (gated) · rest simulated
                       + result forwarded to backend /api/agent/response-log

All state is in-memory; GET /isolation/suggestions serves the dashboard.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import OrderedDict
from typing import Any, Optional

import psutil

from core.event_bus import EventBus
from core.events import AgentFinding, ResponseAction, Severity, ThreatType
from core.executor import kill_process, isolate_machine
from core.alert_queue import OfflineQueueManager
from llm.advisor import call_llm, heuristic_advice, llm_available

log = logging.getLogger("IsolationAdvisor")

MAX_SUGGESTIONS = 100


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")


class IsolationAdvisor:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._suggestions: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._lock = asyncio.Lock()
        self.auto_mode = _env_flag("AIBOO_AUTO_ISOLATE")
        # Real host isolation (firewall changes) stays OFF unless explicitly enabled.
        self.allow_local_actions = _env_flag("AIBOO_ALLOW_LOCAL_ACTIONS")
        self._llm_ready = llm_available()
        self._queue = None  # resolved lazily; DashboardBridge owns the queue singleton

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        self.bus.subscribe(AgentFinding, self._on_finding)
        log.info(
            "IsolationAdvisor started (auto_mode=%s, local_actions=%s, llm=%s)",
            self.auto_mode, self.allow_local_actions, "on" if self._llm_ready else "offline",
        )

    async def stop(self) -> None:
        log.info("IsolationAdvisor stopped")

    # ── ingestion ────────────────────────────────────────────────────────────
    async def _on_finding(self, finding: AgentFinding) -> None:
        if finding.severity not in (Severity.HIGH, Severity.CRITICAL):
            return
        if not finding.actions or set(finding.actions) <= {ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD}:
            return  # informational only — nothing to isolate

        threat_type = finding.threat_type.value
        metadata = finding.metadata or {}
        heuristic_actions, heuristic_text = heuristic_advice(threat_type, metadata, finding.summary)

        suggestion: dict[str, Any] = {
            "id": f"iso_{uuid.uuid4().hex[:10]}",
            "event_id": finding.event_id,
            "agent": finding.agent_name,
            "threat_type": threat_type,
            "severity": finding.severity.value,
            "confidence": round(float(finding.confidence), 2),
            "summary": finding.summary,
            "target": self._pick_target(metadata),
            "recommended_actions": [a.value for a in finding.actions if a not in (ResponseAction.LOG,)],
            "advice": heuristic_text,
            "advice_source": "offline-rules",
            "status": "pending",          # pending | executed | dismissed | failed
            "executed_actions": [],
            "auto": False,
            "timestamp": time.time(),
        }

        # Enrich with LLM advice asynchronously (never blocks the bus)
        asyncio.create_task(self._enrich_with_llm(suggestion, finding))

        async with self._lock:
            self._suggestions[suggestion["id"]] = suggestion
            while len(self._suggestions) > MAX_SUGGESTIONS:
                self._suggestions.popitem(last=False)

        log.info("Isolation suggestion %s created (%s %s → %s)",
                 suggestion["id"], threat_type, finding.severity.value, suggestion["target"])

        # Auto mode: act immediately on critical, high-confidence findings
        if self.auto_mode and finding.severity == Severity.CRITICAL and finding.confidence >= 0.85:
            log.warning("AUTO-ISOLATE triggered for %s", suggestion["id"])
            await self.execute(suggestion["id"], auto=True)

    def _pick_target(self, metadata: dict[str, Any]) -> str:
        for key in ("endpoint", "src_ip", "entity", "user_id", "process_name", "zone"):
            v = metadata.get(key)
            if v and v != "unknown":
                return str(v)
        return "unknown"

    async def _enrich_with_llm(self, suggestion: dict[str, Any], finding: AgentFinding) -> None:
        if not self._llm_ready:
            return
        system = (
            "You are AiBoO's isolation advisor. Given a security finding, reply with "
            "2-3 short sentences: what to isolate/contain FIRST, the exact immediate "
            "action, and one verification step. Tactical, no preamble."
        )
        user = (
            f"Threat: {finding.threat_type.value} (severity={finding.severity.value}, "
            f"confidence={finding.confidence:.0%})\n"
            f"Summary: {finding.summary}\n"
            f"Target: {suggestion['target']}\n"
            f"Proposed actions: {suggestion['recommended_actions']}\n"
            f"Metadata: { {k: str(v) for k, v in list((finding.metadata or {}).items())[:8]} }"
        )
        text = await call_llm(system, user, max_tokens=250)
        if text:
            suggestion["advice"] = text
            suggestion["advice_source"] = "llm"

    # ── operator actions ─────────────────────────────────────────────────────
    async def execute(self, suggestion_id: str, auto: bool = False) -> dict[str, Any]:
        async with self._lock:
            s = self._suggestions.get(suggestion_id)
            if not s:
                return {"ok": False, "error": "suggestion not found"}
            if s["status"] not in ("pending", "failed"):
                return {"ok": False, "error": f"suggestion already {s['status']}"}
            s["status"] = "executing"

        executed: list[str] = []
        notes: list[str] = []
        try:
            for action in s["recommended_actions"]:
                outcome = await self._perform(action, s)
                if outcome:
                    executed.append(action)
                    if isinstance(outcome, str):
                        notes.append(outcome)
            s["status"] = "executed" if executed else "failed"
            s["executed_actions"] = executed
            if notes:
                s["notes"] = "; ".join(notes)
            s["auto"] = auto
            log.warning("Isolation %s executed %s on target %s", suggestion_id, executed, s["target"])
            await self._report_to_backend(s)
        except Exception as e:
            s["status"] = "failed"
            s["notes"] = str(e)
            log.exception("Isolation execution failed for %s", suggestion_id)
        return {"ok": s["status"] == "executed", "suggestion": self._public(s)}

    async def _perform(self, action: str, s: dict[str, Any]) -> Optional[str | bool]:
        """Run one containment action. Returns True, or a note string."""
        target = s["target"]
        if action == "pseudo_lock":
            # Reuse PseudoLockAgent: it subscribes to AgentFinding with PSEUDO_LOCK action
            finding = AgentFinding(
                agent_name="IsolationAdvisor",
                event_id=s["event_id"],
                threat_type=ThreatType(s["threat_type"]) if s["threat_type"] in ThreatType._value2member_map_ else ThreatType.NETWORK_INTRUSION,
                severity=Severity(s["severity"]),
                confidence=max(s["confidence"], 0.9),
                summary=f"Pseudo-lock requested by IsolationAdvisor for {target}",
                actions=[ResponseAction.PSEUDO_LOCK, ResponseAction.LOG],
                metadata={"lock_id": f"lock_{s['event_id']}", "endpoint": target},
            )
            await self.bus.publish(finding)
            return True

        if action in ("terminate_process", "kill_process"):
            pid = self._find_pid(target)
            if pid and kill_process(pid):
                return f"killed PID {pid}"
            return f"no live process matching {target!r}"

        if action == "isolate_asset":
            if not self.allow_local_actions:
                return "simulated (set AIBOO_ALLOW_LOCAL_ACTIONS=true for real firewall isolation)"
            isolate_machine()
            return "firewall isolation applied"

        # revoke_identity / force_logout / lock_zone / challenge_mfa / step_up_auth /
        # notify_* / escalate_soc — forwarded to backend for operator/IDP follow-up
        return "forwarded for enforcement"

    def _find_pid(self, name: str) -> Optional[int]:
        if not name or name == "unknown":
            return None
        name_l = name.lower()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if (proc.info["name"] or "").lower() == name_l:
                    return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    async def dismiss(self, suggestion_id: str) -> dict[str, Any]:
        async with self._lock:
            s = self._suggestions.get(suggestion_id)
            if not s:
                return {"ok": False, "error": "suggestion not found"}
            s["status"] = "dismissed"
        log.info("Isolation suggestion %s dismissed", suggestion_id)
        return {"ok": True, "id": suggestion_id}

    def set_auto(self, enabled: bool) -> dict[str, Any]:
        self.auto_mode = bool(enabled)
        log.warning("IsolationAdvisor auto mode → %s", self.auto_mode)
        return {"auto_mode": self.auto_mode}

    # ── queries ──────────────────────────────────────────────────────────────
    def _public(self, s: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in s.items()}

    def snapshot(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        items = list(self._suggestions.values())
        if status:
            items = [s for s in items if s["status"] == status]
        return [self._public(s) for s in items]

    def stats(self) -> dict[str, Any]:
        by = {"pending": 0, "executed": 0, "dismissed": 0, "failed": 0, "executing": 0}
        for s in self._suggestions.values():
            by[s["status"]] = by.get(s["status"], 0) + 1
        return {"total": len(self._suggestions), "by_status": by,
                "auto_mode": self.auto_mode, "llm": self._llm_ready}

    async def _report_to_backend(self, s: dict[str, Any]) -> None:
        """Best-effort: mirror executed containment to the backend response log."""
        if self._queue is None:
            try:
                self._queue = OfflineQueueManager.get_instance()
            except RuntimeError:
                return  # queue not initialized (standalone/tests) — skip silently
        try:
            await self._queue.add_to_endpoint("response-log", {
                "id": s["id"],
                "suggestion_id": s["id"],
                "event_id": s["event_id"],
                "agent": s["agent"],
                "threat_type": s["threat_type"],
                "severity": s["severity"],
                "target": s["target"],
                "actions": s["executed_actions"],
                "auto": s.get("auto", False),
                "status": s["status"],
                "summary": s["summary"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": s.get("agent", "IsolationAdvisor"),
            })
        except Exception as e:
            log.debug("Failed to mirror response-log to backend: %s", e)
