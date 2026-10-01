"""
gates/gate3_adaptive.py - TriGate Gate 3: IMPACT + the FINAL combined decision.

Gate 3 receives every Gate 2 decision and answers "how bad would it be?":

  Impact score 0-100 from
    * this PC's importance (Endpoints page in the dashboard, or config.ini
      `importance = low|normal|high|critical`; Server = high, Laptop = normal)
    * administrator rights affected (new admin, admin logon)
    * evidence destroyed / monitoring blinded (log cleared, audit policy)
    * persistence (new service / scheduled task survives a reboot)
    * a real, existing account targeted / locked out / deleted
    * working hours (people are using the PC right now)

  Final risk 0-100 = 30% (100 - Trust) + 40% Intent + 30% Impact
    >= 75 CRITICAL, >= 55 HIGH  -> verdict BLOCK  (actions run automatically
                                    ONLY if auto_response = true)
    >= 35 MEDIUM                -> verdict HOLD   (analyst should review)
    <  35 LOW                   -> verdict PASS   (logged only)

The final decision carries all three gate results + reasons + recommended
actions in metadata["trigate"]; the dashboard shows it as 3 bars.
It is also written to the TriGate memory (history for Gate 2, feedback).
"""

from __future__ import annotations

import logging

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, ResponseAction, Severity
from gates.trigate_memory import get_memory
from gates.trigate_patterns import PATTERNS, get_settings

log = logging.getLogger("Gate3.Impact")

IMPORTANCE_POINTS = {"low": 10, "normal": 35, "high": 60, "critical": 80}
WEIGHTS = {"trust": 0.30, "intent": 0.40, "impact": 0.30}


def _factor(points: int, text: str) -> dict:
    return {"points": int(points), "text": text}


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


def impact_level(score: int) -> str:
    return "severe" if score >= 70 else "moderate" if score >= 40 else "limited"


def risk_level(score: int) -> str:
    return "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"


def current_importance(memory=None, settings=None) -> tuple[str, str]:
    """(importance, where it came from)."""
    mem = memory or get_memory()
    imp = mem.get_importance()
    if imp:
        return imp, "set on the dashboard Endpoints page"
    return (settings or get_settings()).default_importance, "config.ini default"


def score_impact(ctx: dict, memory=None, settings=None) -> tuple[int, list[dict], str]:
    settings = settings or get_settings()
    f: list[dict] = []
    pat = PATTERNS.get(ctx["pattern"], PATTERNS["generic"])
    imp, where = current_importance(memory, settings)
    f.append(_factor(IMPORTANCE_POINTS[imp], f"This PC's importance is {imp.upper()} ({where})"))

    if pat.admin_rights:
        f.append(_factor(+15, "Affects administrator rights"))
    if pat.evidence:
        f.append(_factor(+15, "Removes evidence / blinds security monitoring"))
    if pat.persistence:
        f.append(_factor(+10, "Can survive a reboot (persistence)"))

    reason = ctx.get("failure_reason", "").lower()
    if ctx["pattern"] in ("brute_force", "failed_logon"):
        if "does not exist" in reason:
            f.append(_factor(-5, "The account does not exist (nothing to take over)"))
        elif ctx["subject"]:
            f.append(_factor(+10, f"A real account is being targeted ('{ctx['subject']}')"))
    if ctx["pattern"] == "account_lockout":
        f.append(_factor(+10, f"'{ctx['subject']}' is locked out and cannot work"))
    if ctx["pattern"] == "account_deleted":
        f.append(_factor(+10, f"Account '{ctx['subject']}' was removed"))
    if (ctx["subject"] or "").lower() in ("administrator", "admin"):
        f.append(_factor(+10, "The built-in Administrator account is involved"))

    start, end = settings.business_hours
    if start <= int(ctx.get("local_hour", 12)) < end:
        f.append(_factor(+5, "During working hours (people are using this PC)"))

    return _clamp(sum(x["points"] for x in f)), f, imp


def recommend(ctx: dict, level: str) -> list[dict]:
    """Recommended actions. `action` is a dashboard remote action when it can
    be run with one click, otherwise 'manual'. Never targets the admin who
    made a change - only the account / IP that is the problem."""
    if level == "low":
        return [{"action": "log", "target": "", "text": "No action needed - logged for history"}]
    recs: list[dict] = []
    pat, ip, subject = ctx["pattern"], ctx["src_ip"], ctx["subject"]
    exists = "does not exist" not in ctx.get("failure_reason", "").lower()

    if pat in ("brute_force", "failed_logon", "account_lockout", "network_intrusion"):
        if ip and ctx["ip_kind"] in ("public", "private"):
            recs.append({"action": "block_access", "target": ip,
                         "text": f"Block IP {ip} in Windows Firewall"})
        if subject and exists and pat != "network_intrusion":
            recs.append({"action": "revoke_identity", "target": subject,
                         "text": f"Lock account '{subject}' until the owner confirms (not your own account!)"})
    if pat in ("admin_group_add", "account_created") and subject:
        recs.append({"action": "revoke_identity", "target": subject,
                     "text": f"Disable account '{subject}' until someone confirms it is legitimate"})
    if pat in ("log_cleared", "audit_policy_changed"):
        recs.append({"action": "manual", "target": ctx["entity"],
                     "text": f"Ask '{ctx['entity'] or 'the user'}' why logs / audit settings were changed"})
    if pat == "service_installed":
        recs.append({"action": "manual", "target": ctx["service_name"],
                     "text": f"Check service '{ctx['service_name'] or '?'}' (services.msc) and remove it if unknown"})
    if pat == "scheduled_task":
        recs.append({"action": "manual", "target": ctx["task_name"],
                     "text": f"Check scheduled task '{ctx['task_name'] or '?'}' (taskschd.msc) and delete it if unknown"})
    if level == "critical" and pat in ("log_cleared", "audit_policy_changed", "service_installed",
                                       "scheduled_task", "admin_group_add", "malware"):
        recs.append({"action": "isolate_asset", "target": ctx["computer"] or "this PC",
                     "text": "Isolate this PC from the network while you investigate"})
    recs.append({"action": "notify_security", "target": "", "text": "Tell the security team / PC owner"})
    return recs


_EXECUTABLE = {"block_access": ResponseAction.BLOCK_ACCESS, "revoke_identity": ResponseAction.REVOKE_IDENTITY,
               "isolate_asset": ResponseAction.ISOLATE_ASSET, "notify_security": ResponseAction.NOTIFY_SECURITY}


class Gate3Impact:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._evaluate)
        log.info("Gate 3 (Impact) online - importance %s, final TriGate decision",
                 current_importance()[0].upper())

    async def _evaluate(self, decision: GateDecision) -> None:
        if decision.gate != GateLevel.GATE_2:
            return
        meta = dict(decision.metadata or {})
        tri = dict(meta.get("trigate") or {})
        ctx, trust, intent = tri.get("context"), tri.get("trust"), tri.get("intent")
        if not (ctx and trust and intent):
            return

        impact, factors, importance = score_impact(ctx)
        risk = _clamp(WEIGHTS["trust"] * (100 - trust["score"])
                      + WEIGHTS["intent"] * intent["score"]
                      + WEIGHTS["impact"] * impact)
        level = risk_level(risk)
        verdict = GateVerdict.BLOCK if level in ("critical", "high") else \
            GateVerdict.HOLD if level == "medium" else GateVerdict.PASS
        recs = recommend(ctx, level)
        actions = [_EXECUTABLE[r["action"]] for r in recs if r["action"] in _EXECUTABLE]

        tri["impact"] = {"score": impact, "level": impact_level(impact), "factors": factors,
                         "importance": importance}
        tri["risk"] = {"score": risk, "level": level, "weights": WEIGHTS}
        tri["recommended"] = recs
        tri["pattern"] = ctx["pattern"]
        tri["entity"] = ctx["entity"]
        tri["subject"] = ctx["subject"]
        meta["trigate"] = tri

        explanation = (
            f"Risk {risk}/100 ({level.upper()}) - {ctx['pattern_label']}"
            f"{' by ' + repr(ctx['entity']) if ctx['entity'] else ''}. "
            f"Trust {trust['score']} ({trust['level']}), Intent {intent['score']} ({intent['level']}), "
            f"Impact {impact} ({impact_level(impact)})."
        )

        get_memory().record_event(decision.event_id, ctx["entity"], ctx["pattern"], risk,
                                  subject=ctx["subject"])
        get_memory().maybe_save()

        if verdict == GateVerdict.PASS:
            log.info("TriGate PASS: %s", explanation)
        else:
            log.warning("TriGate %s: %s", verdict.value.upper(), explanation)
        await self.bus.publish(GateDecision(
            gate=GateLevel.GATE_3,
            event_id=decision.event_id,
            threat_type=decision.threat_type,
            severity=Severity(level),
            verdict=verdict,
            confidence=round(min(0.95, 0.5 + 0.03 * (len(trust["factors"]) + len(intent["factors"])
                                                   + len(factors))), 2),
            reason=explanation,
            actions=actions,
            metadata=meta,
        ))


# Backwards-compatible name
Gate3Adaptive = Gate3Impact
