"""
gates/gate2_behavioural.py - TriGate Gate 2: INTENT  ("is this an attack?")

Receives EVERY Gate 1 decision (the old gate only ran on HOLD) and produces
an Intent score 0-100 (100 = clearly malicious):

  * attack pattern of the event (brute force, log cleared, new admin, new
    service / scheduled task, ...) with its MITRE ATT&CK technique
  * suspicious command in a service / task / process (powershell, temp, ...)
  * history from the TriGate memory (saved on disk, last 7 days):
      - other alerts for the same user in 24 h / 7 days
      - attack chains: new account -> made admin, alerts -> log cleared
  * time of day in the PC's LOCAL time (old gate used UTC - wrong in India)
  * threat intel on the source IP: your blocklist + AbuseIPDB (optional)
  * the ingestor's anomaly score (unusual event rate)
  * analyst feedback: "False alarm" lowers, "Confirmed threat" raises

Fixed bugs from the old gate: `reason` used before assignment (crash),
off-hours check in UTC, ran only for HOLD.
"""

from __future__ import annotations

import logging

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict
from gates.threat_intel_lookup import get_threat_intel
from gates.trigate_memory import get_memory
from gates.trigate_patterns import PATTERNS, command_is_suspicious, get_settings

log = logging.getLogger("Gate2.Intent")

_NORMAL_PROGRAM_DIRS = ("c:\\windows\\system32\\", "c:\\program files\\", "c:\\program files (x86)\\",
                        "%systemroot%\\system32\\", "\\systemroot\\system32\\")


def _factor(points: int, text: str) -> dict:
    return {"points": int(points), "text": text}


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


def intent_level(score: int) -> str:
    return "malicious" if score >= 70 else "suspicious" if score >= 40 else "probably harmless"


async def score_intent(ctx: dict, memory=None, intel=None, settings=None) -> tuple[int, list[dict]]:
    mem = memory or get_memory()
    intel = intel or get_threat_intel()
    settings = settings or get_settings()
    f: list[dict] = []
    pat = PATTERNS.get(ctx["pattern"], PATTERNS["generic"])
    entity, subject = ctx["entity"], ctx["subject"]

    # --- 1. what kind of event --------------------------------------------
    if ctx.get("test_event") and ctx.get("test_intent") is not None and ctx["pattern"] in (
            ctx["threat_type"], "generic"):
        f.append(_factor(ctx["test_intent"], f"Test event from the dashboard (severity {ctx['severity_in']})"))
    else:
        mitre = f" - MITRE {pat.mitre_id} {pat.mitre_name}" if pat.mitre_id else ""
        f.append(_factor(pat.base_intent, f"{pat.label}{mitre}"))

    # Behaviour analytics: each reason it found (new account in use, unusual hour,
    # first remote logon, ...) is shown with its own points.
    for r in (ctx.get("behaviour_reasons") or [])[:5]:
        if r.get("text"):
            f.append(_factor(max(-20, min(25, int(r.get("points") or 0))), r["text"]))

    if ctx["pattern"] == "brute_force" and ctx["failed_attempts"] >= 20:
        f.append(_factor(+10, f"Very many attempts ({ctx['failed_attempts']})"))

    cmd = ctx.get("command") or ""
    if ctx["pattern"] in ("service_installed", "scheduled_task", "process_started") and cmd:
        if command_is_suspicious(cmd):
            f.append(_factor(+15, f"Runs a suspicious command: {cmd[:90]}"))
        elif cmd.lower().strip('"').startswith(_NORMAL_PROGRAM_DIRS):
            f.append(_factor(-10, "Program is in a normal Windows / Program Files folder"))

    # --- 2. history (memory on disk, 24 h - 7 days) ---------------------------
    if entity:
        day = mem.count_events(entity=entity, hours=24, exclude_event=ctx["event_id"])
        week = mem.count_events(entity=entity, hours=24 * 7, exclude_event=ctx["event_id"])
        if day:
            f.append(_factor(min(20, 5 * day), f"{day} other alert(s) for '{entity}' in the last 24 hours"))
        if week - day >= 3:
            f.append(_factor(+10, f"{week} alerts for '{entity}' in the last 7 days"))

    if ctx["pattern"] == "admin_group_add" and subject:
        age = mem.hours_since(pattern="account_created", subject=subject)
        if age is not None and age <= 24:
            f.append(_factor(+15, "Brand-new account was made administrator (typical attack chain)"))
    if pat.evidence:
        others = mem.count_events(hours=24, exclude_event=ctx["event_id"])
        if others:
            f.append(_factor(+10, f"Happened after {others} other alert(s) today (covering tracks?)"))

    # --- 3. time of day (LOCAL time of this PC) -------------------------------
    start, end = settings.business_hours
    hour = int(ctx.get("local_hour", 12))
    if not (start <= hour < end):
        f.append(_factor(+10, f"Happened at {hour:02d}:{int(ctx.get('local_minute', 0)):02d}, "
                              f"outside working hours ({start}:00-{end}:00)"))

    # --- 4. threat intel on the source IP ---------------------------------
    if ctx["src_ip"] and ctx["ip_kind"] in ("public", "private"):
        try:
            hit = await intel.check(ctx["src_ip"])
        except Exception as exc:                     # intel must never break the gate
            log.debug("threat intel failed: %s", exc)
            hit = None
        if hit and hit.malicious:
            f.append(_factor(+30 if hit.source == "blocklist" else +25, hit.detail))
        elif hit is not None and hit.score == 0:
            f.append(_factor(-5, f"{hit.detail} (clean)"))

    # --- 5. unusual event rate -----------------------------------------------
    if ctx.get("anomaly_score", 0) >= 0.8:
        f.append(_factor(+5, "Unusually many events of this type right now"))

    # --- 6. learning from the analyst -------------------------------------
    fb = mem.feedback_for(ctx["pattern"], entity)
    if fb["false_alarm"]:
        f.append(_factor(-min(60, 25 * fb["false_alarm"]),
                         f"You marked this as a false alarm {fb['false_alarm']}x before"))
    if fb["confirmed"]:
        f.append(_factor(min(20, 10 * fb["confirmed"]),
                         f"You confirmed this as a real threat {fb['confirmed']}x before"))

    return _clamp(sum(x["points"] for x in f)), f


class Gate2Intent:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._evaluate)
        log.info("Gate 2 (Intent) online - patterns, 7-day history, threat intel, learning")

    async def _evaluate(self, decision: GateDecision) -> None:
        if decision.gate != GateLevel.GATE_1:
            return
        tri = dict((decision.metadata or {}).get("trigate") or {})
        ctx = tri.get("context")
        if not ctx:
            return
        score, factors = await score_intent(ctx)
        level = intent_level(score)
        verdict = GateVerdict.BLOCK if score >= 70 else GateVerdict.HOLD if score >= 40 else GateVerdict.PASS
        top = "; ".join(x["text"] for x in sorted(factors, key=lambda x: -x["points"])[:2])
        tri["intent"] = {"score": score, "level": level, "factors": factors,
                         "mitre": {"id": ctx.get("mitre_id"), "name": ctx.get("mitre_name")}}
        log.info("Gate 2 Intent %d (%s) for %s [%s]", score, level, ctx["entity"] or "?", ctx["pattern"])
        await self.bus.publish(GateDecision(
            gate=GateLevel.GATE_2,
            event_id=decision.event_id,
            threat_type=decision.threat_type,
            severity=decision.severity,
            verdict=verdict,
            confidence=round(min(0.95, 0.55 + 0.05 * len(factors)), 2),
            reason=f"Intent {score}/100 ({level}): {top}",
            actions=[],
            metadata={**(decision.metadata or {}), "trigate": tri},
        ))


# Backwards-compatible name
Gate2Behavioural = Gate2Intent
