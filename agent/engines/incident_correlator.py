"""
engines/incident_correlator.py - links TriGate decisions into INCIDENTS.

Why: the old CorrelationEngine only links findings whose *threat-type
combinations* match a fixed list within 5 minutes. Real Windows events almost
never form those combinations, so the dashboard showed "Correlated (0)".

How this works (simple):
  1. Every final TriGate decision (Gate 3) with risk >= MIN_RISK (default 35 =
     HOLD or BLOCK) is remembered for `window_minutes` (default 60).
  2. Each decision has "keys": the user it is about, the user who did it, the
     outside IP and the computer it came from. Two decisions are RELATED when
     they share a key (e.g. same user, same attacker IP).
  3. Each decision is mapped to an ATTACK STAGE (MITRE ATT&CK tactic), e.g.
        failed logons / password guessing  -> Credential Access
        new account / service / task       -> Persistence
        user added to Administrators       -> Privilege Escalation
        security log cleared / audit off   -> Defense Evasion
  4. An incident alert (CorrelatedAlert) is raised when related decisions
     cover 2+ different stages (an attack chain), or when the same user / IP
     gets 3+ BLOCK decisions (repeated high-risk activity).
     2 stages -> HIGH, 3+ stages -> CRITICAL.
  5. If the incident grows (new stage / more events) the SAME alert_id is sent
     again with the bigger picture - the dashboard updates the card.

Nothing is executed here - it only explains how alerts belong together.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from core.event_bus import EventBus
from core.events import (
    AgentFinding, CorrelatedAlert, GateDecision, GateLevel, ResponseAction,
    Severity, ThreatType,
)

log = logging.getLogger("IncidentCorrelator")

MIN_RISK = 35                 # HOLD or BLOCK decisions only (PASS = normal activity)
DEFAULT_WINDOW_MINUTES = 60
REPEAT_BLOCKS = 3             # same key, this many BLOCKs -> incident

# Attack stages in kill-chain order (MITRE ATT&CK tactics)
STAGES = [
    ("initial_access", "Initial Access"),
    ("credential_access", "Credential Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("lateral_movement", "Lateral Movement"),
    ("command_and_control", "Command and Control"),
    ("impact", "Impact"),
]
STAGE_ORDER = {k: i for i, (k, _) in enumerate(STAGES)}
STAGE_LABEL = dict(STAGES)

PATTERN_STAGE = {
    "brute_force": "credential_access",
    "failed_logon": "credential_access",
    "account_lockout": "credential_access",
    "explicit_credentials": "credential_access",
    "process_started": "execution",
    "account_created": "persistence",
    "service_installed": "persistence",
    "scheduled_task": "persistence",
    "admin_group_add": "privilege_escalation",
    "admin_logon": "privilege_escalation",
    "privilege_use": "privilege_escalation",
    "log_cleared": "defense_evasion",
    "audit_policy_changed": "defense_evasion",
    "account_deleted": "defense_evasion",
    "network_share": "lateral_movement",
    "geo_velocity": "initial_access",
    "ghost_login": "initial_access",
    "behavioral_anomaly": "initial_access",
    "anomalous_behavior": "initial_access",
    "network_intrusion": "initial_access",
    "phishing": "initial_access",
    "threat_intel_alert": "command_and_control",
    "malware": "execution",
    "memory_threat": "execution",
    "ransomware_prelude": "impact",
}


def stage_of(pattern: str) -> Optional[str]:
    return PATTERN_STAGE.get(str(pattern or "").lower())


@dataclass
class _Item:
    event_id: str
    ts: float
    pattern: str
    label: str
    stage: Optional[str]
    risk: int
    level: str
    verdict: str
    keys: frozenset
    summary: str
    entity: str = ""
    subject: str = ""
    src_ip: str = ""


@dataclass
class _Incident:
    alert_id: str
    keys: set = field(default_factory=set)
    items: list = field(default_factory=list)
    sent_signature: str = ""


def _keys_from(tri: dict, ctx: dict) -> frozenset:
    keys = set()
    for name in ("entity", "subject", "actor"):
        v = str(ctx.get(name) or tri.get(name) or "").strip().lower()
        if v and v not in ("unknown", "-", "system", "local service", "network service"):
            keys.add(f"user:{v}")
    ip = str(ctx.get("src_ip") or "").strip()
    if ip and ctx.get("ip_kind") in ("public", "private"):
        keys.add(f"ip:{ip}")
    ws = str(ctx.get("workstation") or "").strip().lower()
    if ws and ws not in ("-", "unknown") and ctx.get("device_kind") == "other":
        keys.add(f"pc:{ws}")
    return frozenset(keys)


class IncidentCorrelator:
    def __init__(self, bus: EventBus, window_minutes: float = DEFAULT_WINDOW_MINUTES,
                 min_risk: int = MIN_RISK, clock=time.time) -> None:
        self.bus = bus
        self.window = max(5.0, float(window_minutes or DEFAULT_WINDOW_MINUTES)) * 60
        self.min_risk = int(min_risk)
        self._clock = clock
        self._items: list[_Item] = []
        self._incidents: list[_Incident] = []
        self.emitted = 0

    def start(self) -> None:
        self.bus.subscribe(GateDecision, self._on_decision)
        log.info("Incident correlator online - links TriGate alerts by user / IP / PC "
                 "within %d min (attack-chain stages)", int(self.window // 60))

    # ------------------------------------------------------------------
    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        self._items = [i for i in self._items if i.ts >= cutoff]
        alive = []
        for inc in self._incidents:
            inc.items = [i for i in inc.items if i.ts >= cutoff]
            if inc.items:
                alive.append(inc)
        self._incidents = alive

    def _to_item(self, d: GateDecision) -> Optional[_Item]:
        if int(getattr(d.gate, "value", d.gate)) != GateLevel.GATE_3.value:
            return None
        tri = dict((d.metadata or {}).get("trigate") or {})
        ctx = dict(tri.get("context") or {})
        risk = int((tri.get("risk") or {}).get("score") or 0)
        if risk < self.min_risk:
            return None
        pattern = str(tri.get("pattern") or ctx.get("pattern") or "").lower()
        if (d.metadata or {}).get("source_engine") == "IncidentCorrelator":
            return None
        keys = _keys_from(tri, ctx)
        if not keys:
            return None
        label = str(ctx.get("pattern_label") or pattern.replace("_", " ") or "alert")
        who = ctx.get("entity") or ctx.get("subject") or ""
        desc = str(ctx.get("description") or "")[:160]
        summary = f"{label}" + (f" - '{who}'" if who else "") + (f" from {ctx['src_ip']}" if ctx.get("src_ip") else "")
        summary += f" (risk {risk}, {getattr(d.verdict, 'value', d.verdict)})"
        if desc:
            summary += f": {desc}"
        return _Item(
            event_id=str(d.event_id), ts=self._clock(), pattern=pattern, label=label,
            stage=stage_of(pattern), risk=risk, level=str((tri.get("risk") or {}).get("level") or ""),
            verdict=str(getattr(d.verdict, "value", d.verdict)), keys=keys, summary=summary,
            entity=str(ctx.get("entity") or ""), subject=str(ctx.get("subject") or ""),
            src_ip=str(ctx.get("src_ip") or ""),
        )

    async def _on_decision(self, d: GateDecision) -> None:
        try:
            item = self._to_item(d)
        except Exception as exc:                 # never break the bus
            log.debug("correlator skipped decision: %s", exc)
            return
        if item is None:
            return
        alert = self.add(item)
        if alert is not None:
            await self.bus.publish(alert)

    # ------------------------------------------------------------------
    def add(self, item: _Item) -> Optional[CorrelatedAlert]:
        """Add one decision; returns a CorrelatedAlert when an incident is new
        or has grown, else None. (Synchronous so it is easy to test.)"""
        now = item.ts
        self._prune(now)
        if any(i.event_id == item.event_id for i in self._items):
            return None
        self._items.append(item)

        # incidents this item touches (merge them if it bridges several)
        touching = [inc for inc in self._incidents if inc.keys & item.keys]
        if touching:
            inc = touching[0]
            for other in touching[1:]:
                inc.keys |= other.keys
                inc.items.extend(x for x in other.items if x not in inc.items)
                self._incidents.remove(other)
        else:
            related = [i for i in self._items if i is not item and i.keys & item.keys]
            if not related:
                return None
            inc = _Incident(alert_id="")
            for r in related:
                inc.keys |= r.keys
                inc.items.append(r)
            self._incidents.append(inc)
        inc.keys |= item.keys
        if item not in inc.items:
            inc.items.append(item)
        inc.items.sort(key=lambda x: x.ts)
        return self._evaluate(inc)

    def _evaluate(self, inc: _Incident) -> Optional[CorrelatedAlert]:
        stages = sorted({i.stage for i in inc.items if i.stage}, key=STAGE_ORDER.get)
        blocks = [i for i in inc.items if i.verdict == "block"]
        chain = len(stages) >= 2
        repeated = len(blocks) >= REPEAT_BLOCKS
        if not (chain or repeated):
            return None

        signature = f"{','.join(stages)}|{len(inc.items)}"
        if signature == inc.sent_signature:
            return None
        if not inc.alert_id:
            seed = inc.items[0].event_id + "|" + ",".join(sorted(inc.keys))
            inc.alert_id = "inc_" + hashlib.sha1(seed.encode()).hexdigest()[:12]
        inc.sent_signature = signature

        if chain and len(stages) >= 3:
            severity = Severity.CRITICAL
        elif chain or max(i.risk for i in inc.items) >= 75:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        max_risk = max(i.risk for i in inc.items)
        confidence = round(min(0.95, 0.55 + 0.1 * len(stages) + 0.03 * len(inc.items)), 2)

        users = sorted({k[5:] for k in inc.keys if k.startswith("user:")})
        ips = sorted({k[3:] for k in inc.keys if k.startswith("ip:")})
        pcs = sorted({k[3:] for k in inc.keys if k.startswith("pc:")})
        about = []
        if users:
            about.append("user " + ", ".join(f"'{u}'" for u in users[:3]))
        if ips:
            about.append("IP " + ", ".join(ips[:3]))
        if pcs:
            about.append("PC " + ", ".join(pcs[:3]))
        span_min = max(1, int(round((inc.items[-1].ts - inc.items[0].ts) / 60)))
        if chain:
            title = "Possible attack chain: " + " -> ".join(STAGE_LABEL[s] for s in stages)
        else:
            title = f"Repeated high-risk activity ({len(blocks)} BLOCK decisions)"
        description = (f"{title}. {len(inc.items)} linked alerts for {' / '.join(about) or 'the same target'} "
                       f"within {span_min} min (highest risk {max_risk}).")

        findings = [
            AgentFinding(
                agent_name=f"TriGate ({STAGE_LABEL.get(i.stage, 'Other')})",
                event_id=i.event_id,
                threat_type=ThreatType.CORRELATED_ATTACK,
                severity=Severity(i.level) if i.level in ("low", "medium", "high", "critical") else Severity.MEDIUM,
                confidence=1.0,
                summary=i.summary,
                actions=[],
                metadata={"pattern": i.pattern, "stage": i.stage, "risk": i.risk, "verdict": i.verdict,
                          "entity": i.entity, "subject": i.subject, "src_ip": i.src_ip},
            )
            for i in inc.items
        ]
        actions = [ResponseAction.NOTIFY_SECURITY]
        if ips:
            actions.append(ResponseAction.BLOCK_ACCESS)
        if users:
            actions.append(ResponseAction.REVOKE_IDENTITY)
        self.emitted += 1
        log.warning("INCIDENT %s (%s): %s", inc.alert_id, severity.value.upper(), description)
        alert = CorrelatedAlert(
            alert_id=inc.alert_id,
            threat_type=ThreatType.CORRELATED_ATTACK,
            severity=severity,
            confidence=confidence,
            description=description,
            findings=findings,
            actions=actions,
        )
        # extra info for the dashboard (not a dataclass field; the bridge adds it)
        alert.incident = {
            "stages": [{"key": s, "label": STAGE_LABEL[s]} for s in stages],
            "users": users, "ips": ips, "pcs": pcs, "max_risk": max_risk,
            "count": len(inc.items), "span_minutes": span_min,
            "kind": "attack_chain" if chain else "repeated",
        }
        return alert

    def stats(self) -> dict[str, Any]:
        return {"open_incidents": len(self._incidents), "tracked": len(self._items),
                "emitted": self.emitted, "window_minutes": int(self.window // 60)}
