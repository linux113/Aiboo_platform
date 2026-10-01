"""
gates/gate1_perimeter.py - TriGate Gate 1: TRUST  ("who is this, and can we trust them?")

Every ThreatEvent goes through Gate 1. It produces a Trust score 0-100
(100 = fully trusted, 0 = not trusted at all) from REAL Windows data:

  * failed logons / password guessing (brute force)       -> trust down
  * remote logon (RDP / network / clear-text) vs local    -> remote = down, local = up
  * internet IP vs LAN IP                                 -> internet = down
  * user / IP seen before in successful logons (memory)  -> known = up, new = down
  * user name that does not exist, account lockout       -> down
  * logon attempt from another computer (workstation)    -> down
  * account created only hours ago, gave rights to self  -> down
  * analyst said "False alarm" for this before           -> up

Gate 1 never drops an event: it always forwards its decision to Gate 2.
(The old 5-second de-duplication + burst filter is gone - it hid brute
force. Only a true duplicate of the same Windows record is skipped.)
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, Severity, ThreatEvent
from gates.trigate_memory import get_memory
from gates.trigate_patterns import (
    clean, classify, ip_kind, local_account, local_time, logon_kind,
    test_event_intent, this_pc_names,
)

log = logging.getLogger("Gate1.Trust")

TRUST_START = 70          # neutral starting point
_LOGON_PATTERNS = {"brute_force", "failed_logon", "account_lockout", "explicit_credentials"}
_SEEN_MAX = 5000


def _factor(points: int, text: str) -> dict:
    return {"points": int(points), "text": text}


def _clamp(v: float) -> int:
    return int(max(0, min(100, round(v))))


def trust_level(score: int) -> str:
    return "trusted" if score >= 70 else "uncertain" if score >= 40 else "untrusted"


def _describe(p: dict, pat, event) -> str:
    """Best human-readable sentence for the card."""
    for key in ("description", "message", "reason", "summary", "details"):
        v = p.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if pat.key == "generic":
        tt = getattr(event.threat_type, "value", str(event.threat_type or ""))
        src = event.source or "agent"
        return f"{pat.label} ({str(tt).replace('_', ' ')}) reported by {src}"
    return pat.label


def build_context(event: ThreatEvent) -> dict:
    """Everything the three gates need about one event (JSON-safe)."""
    p = event.payload or {}
    pat = classify(event)
    # Windows writes local accounts as "THISPC\\alice"; show (and act on) "alice".
    pcs = this_pc_names(p.get("computer_name"), p.get("device_id"))
    user = local_account(p.get("user_id"), pcs)
    actor = local_account(p.get("actor"), pcs)
    target = local_account(p.get("target_user"), pcs)

    if pat.key in _LOGON_PATTERNS or not actor:
        entity = user or actor or local_account(p.get("entity_id"), pcs)
    else:
        entity = actor                                   # admin change: who did it
    pc_full = {clean(p.get("computer_name")).lower(), clean(p.get("device_id")).lower()} - {""}
    if entity and (entity.lower() in pcs or entity.lower() in pc_full):
        entity = ""        # the ingestor fell back to the PC name: no real user known
    subject = target or user or entity                   # who / what it was done to

    command = clean(p.get("image_path")) or clean(p.get("task_command")) or clean(p.get("command_line"))
    try:
        attempts = int(p.get("failed_attempts") or 0)
    except (TypeError, ValueError):
        attempts = 0
    try:
        anomaly = float(p.get("anomaly_score") or 0)
    except (TypeError, ValueError):
        anomaly = 0.0
    src_ip = clean(p.get("src_ip"))
    when = local_time(event.timestamp)
    return {
        "event_id": event.event_id,
        "source": event.source,
        "threat_type": getattr(event.threat_type, "value", str(event.threat_type)),
        "severity_in": getattr(event.severity, "value", str(event.severity)),
        "pattern": pat.key,
        "pattern_label": pat.label,
        "mitre_id": pat.mitre_id,
        "mitre_name": pat.mitre_name,
        "event_id_raw": p.get("event_id_raw"),
        "description": _describe(p, pat, event)[:300],
        "entity": entity,
        "subject": subject,
        "user_id": user,
        "actor": actor,
        "target_user": target,
        "src_ip": src_ip,
        "ip_kind": ip_kind(src_ip),
        "logon_type": clean(p.get("logon_type")),
        "logon_kind": logon_kind(p.get("logon_type")) or ("runas" if pat.key == "explicit_credentials" else ""),
        "failure_reason": clean(p.get("failure_reason")),
        "failed_attempts": attempts,
        "workstation": clean(p.get("workstation")),
        "computer": clean(p.get("computer_name")),
        "group": clean(p.get("group")),
        "privileged_group": bool(p.get("privileged_group")),
        "service_name": clean(p.get("service_name")),
        "task_name": clean(p.get("task_name")),
        "command": command[:300],
        "anomaly_score": anomaly,
        "test_event": bool(p.get("test_event")),
        "test_intent": test_event_intent(event),
        "local_time": when.strftime("%Y-%m-%d %H:%M"),
        "local_hour": when.hour,
        "local_minute": when.minute,
    }


def score_trust(ctx: dict, memory=None) -> tuple[int, list[dict]]:
    """Trust score 0-100 + the list of reasons (points can be + or -)."""
    mem = memory or get_memory()
    f: list[dict] = []
    pat = ctx["pattern"]
    entity, subject = ctx["entity"], ctx["subject"]

    if not entity:
        f.append(_factor(-15, "Could not tell which user did this"))

    # --- authentication confidence -----------------------------------
    if pat == "brute_force":
        n = ctx["failed_attempts"] or 5
        f.append(_factor(-35, f"{n} failed logons in a few minutes (password guessing)"))
    elif pat == "failed_logon":
        f.append(_factor(-10, f"Failed logon ({ctx['failure_reason'] or 'wrong password'})"))
    if "does not exist" in ctx["failure_reason"].lower():
        f.append(_factor(-10, "Tried a user name that does not exist (guessing names)"))
    if pat == "account_lockout" or "locked out" in ctx["failure_reason"].lower():
        f.append(_factor(-15, "The account got locked out"))

    # --- how they logged on --------------------------------------------
    lk = ctx["logon_kind"]
    if lk == "clear_text":
        f.append(_factor(-25, "Password sent in clear text over the network"))
    elif lk == "remote":
        f.append(_factor(-15, f"Remote logon ({ctx['logon_type']})"))
    elif lk == "runas":
        if ctx["actor"] and ctx["user_id"] and ctx["actor"].lower() != ctx["user_id"].lower():
            f.append(_factor(-5, f"'{ctx['actor']}' used the password of '{ctx['user_id']}' (RunAs)"))
        else:
            f.append(_factor(-5, "Logon with different credentials (RunAs)"))
    elif lk == "local":
        f.append(_factor(+5, "Logon at this PC's own keyboard (local)"))

    # --- where from -----------------------------------------------------
    ip, kind = ctx["src_ip"], ctx["ip_kind"]
    if kind == "public":
        f.append(_factor(-20, f"Came from an internet address ({ip})"))
    elif kind == "private":
        f.append(_factor(-5, f"Came from another PC on the network ({ip})"))
    ws, me = ctx["workstation"].lower(), ctx["computer"].lower().split(".")[0]
    if ws and me and ws != me and kind not in ("public", "private"):
        f.append(_factor(-10, f"Logon attempt came from another computer '{ctx['workstation']}'"))

    # --- memory: is this user / IP known? ------------------------------
    if entity:
        known_user = mem.user_known(entity)
        if known_user:
            f.append(_factor(+10, f"'{entity}' normally logs in on this PC"))
        elif pat in _LOGON_PATTERNS:
            f.append(_factor(-10, f"'{entity}' has never logged in successfully on this PC"))
        if kind in ("public", "private") and known_user:
            if mem.ip_known_for_user(entity, ip):
                f.append(_factor(+10, f"'{entity}' has logged in from {ip} before"))
            else:
                f.append(_factor(-10, f"First time '{entity}' is seen from {ip}"))

    # --- the account that was changed ----------------------------------
    if pat in ("admin_group_add", "group_add") and subject:
        age = mem.hours_since(pattern="account_created", subject=subject)
        if age is not None and age <= 24:
            f.append(_factor(-20, f"'{subject}' was created only {_ago(age)} ago"))
        if entity and subject.lower() == entity.lower():
            f.append(_factor(-15, "The user gave rights to their own account"))

    # --- learning from the analyst --------------------------------------
    fb = mem.feedback_for(pat, entity)
    if fb["false_alarm"]:
        f.append(_factor(min(20, 10 * fb["false_alarm"]),
                         f"You marked this as a false alarm before ({fb['false_alarm']}x)"))

    score = _clamp(TRUST_START + sum(x["points"] for x in f))
    return score, f


def _ago(hours: float) -> str:
    if hours < 1:
        return f"{max(1, int(hours * 60))} min"
    return f"{hours:.0f} h"


class Gate1Trust:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._seen: "OrderedDict[str, None]" = OrderedDict()

    def start(self) -> None:
        self.bus.subscribe(ThreatEvent, self._evaluate)
        log.info("Gate 1 (Trust) online - every event is scored, nothing is dropped")

    def _is_true_duplicate(self, event: ThreatEvent) -> bool:
        """Same Windows record read twice (e.g. after a reconnect)."""
        rec = (event.payload or {}).get("record_number")
        if rec in (None, ""):
            return False
        key = f"{event.source}|{(event.payload or {}).get('log_name', '')}|{rec}"
        if key in self._seen:
            return True
        self._seen[key] = None
        if len(self._seen) > _SEEN_MAX:
            self._seen.popitem(last=False)
        return False

    async def _evaluate(self, event: ThreatEvent) -> None:
        if self._is_true_duplicate(event):
            log.debug("Gate 1: skipped duplicate Windows record %s", event.payload.get("record_number"))
            return
        ctx = build_context(event)
        score, factors = score_trust(ctx)
        level = trust_level(score)
        verdict = GateVerdict.PASS if score >= 70 else GateVerdict.HOLD if score >= 40 else GateVerdict.BLOCK
        top = "; ".join(x["text"] for x in sorted(factors, key=lambda x: x["points"])[:2]) or "nothing unusual"
        decision = GateDecision(
            gate=GateLevel.GATE_1,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=event.severity,
            verdict=verdict,
            confidence=round(min(0.95, 0.55 + 0.05 * len(factors)), 2),
            reason=f"Trust {score}/100 ({level}): {top}",
            actions=[],
            metadata={
                "payload": _slim_payload(event.payload or {}, ctx),
                "trigate": {
                    "context": ctx,
                    "trust": {"score": score, "level": level, "factors": factors},
                },
            },
        )
        log.info("Gate 1 Trust %d (%s) for %s [%s]", score, level, ctx["entity"] or "?", ctx["pattern"])
        await self.bus.publish(decision)


def _slim_payload(p: dict, ctx: dict) -> dict:
    """Small payload kept on the decision (used by the response engine).

    user_id is set to the account an action should apply to: for "user X
    was added to Administrators" that is X - NOT the admin who did it."""
    out = {k: p.get(k) for k in ("event_id_raw", "record_number", "computer_name", "src_ip",
                                 "device_id", "description", "pid", "process_name")
           if p.get(k) not in (None, "")}
    out["user_id"] = ctx["subject"] or ctx["entity"] or "unknown"
    out["actor"] = ctx["actor"] or ctx["entity"]
    return out


# Backwards-compatible name (orchestrator / imports use Gate1Perimeter)
Gate1Perimeter = Gate1Trust
