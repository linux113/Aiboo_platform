"""
engines/behaviour_analytics.py - real per-user behaviour baselines (UEBA).

The old UEBA / Behavioral-DNA engines only "learned" from ALERTS (successful
logons are LOW severity and never reach them), so they had no idea what
normal looks like and produced vague "Unusual behaviour" cards.

This engine learns from every SUCCESSFUL Windows logon (event 4624) of a real
person (computer accounts, SYSTEM, DWM-/UMFD- etc. are skipped):

    * at which HOURS the user normally logs on          (24-hour histogram)
    * HOW they log on: local (keyboard / unlock), remote desktop (RDP),
      network (file share, ...)                         (counts per kind)
    * FROM WHICH IPs (remote / network logons)
    * on how many different DAYS we have seen them      (learning period)

and raises a BEHAVIORAL_ANOMALY event (-> TriGate card "Unusual behaviour")
with plain-English reasons when a logon does not fit:

    1. "Account 'x' was created N min ago and is already being used"
       (no learning needed - a classic attacker move)
    2. Logon at an hour the user practically never logs on
    3. First remote-desktop / network logon ever for a user who always
       logs on locally
    4. First logon from a new IP address

Checks 2-4 only start after a learning period (default: 20 logons on 3+
different days) so a fresh install does not raise false alarms.

config.ini (all optional):
    behaviour_analytics   = true
    behaviour_min_logons  = 20
    behaviour_min_days    = 3
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Callable, Optional

from core.events import Severity, ThreatEvent, ThreatType

log = logging.getLogger("BehaviourAnalytics")

LOGON_KIND = {"2": "local", "7": "local", "11": "local", "10": "remote", "3": "network"}
KIND_TEXT = {"local": "at the keyboard / unlock", "remote": "with Remote Desktop (RDP)",
             "network": "over the network (file share / remote tool)"}
_SKIP_USERS = {"system", "local service", "network service", "anonymous logon", "-", "",
               "defaultaccount", "wdagutilityaccount"}
_SKIP_PREFIXES = ("dwm-", "umfd-", "font driver host", "window manager")

NEW_ACCOUNT_MINUTES = 60
RATE_LIMIT_SECONDS = 30 * 60
MAX_DAYS_KEPT = 30
MAX_IPS = 20
RARE_HOUR_SHARE = 0.02          # < 2 % of the user's logons in this hour +/- 1


def logon_kind_of(logon_type: Any) -> Optional[str]:
    """'local' / 'remote' / 'network' from the logon type number ("10") or the
    parser's text ("remote desktop (RDP)"). None = service / batch / RunAs."""
    t = str(logon_type or "").strip().lower()
    if t.startswith("type "):
        t = t[5:].strip()
    if t in LOGON_KIND:
        return LOGON_KIND[t]
    if "remote desktop" in t or "rdp" in t:
        return "remote"
    if "network" in t:
        return "network"
    if any(m in t for m in ("interactive", "unlock", "cached")):
        return "local"
    return None


def _norm(user: Any) -> str:
    u = str(user or "").strip()
    if "\\" in u:
        u = u.split("\\")[-1]
    if "@" in u:
        u = u.split("@")[0]
    return u.lower()


def is_person(user: Any) -> bool:
    u = _norm(user)
    return bool(u) and u not in _SKIP_USERS and not u.endswith("$") and not u.startswith(_SKIP_PREFIXES)


def _is_remote_ip(ip: str) -> bool:
    ip = (ip or "").strip()
    return bool(ip) and ip not in ("-", "::1", "127.0.0.1", "0.0.0.0", "unknown") and not ip.startswith("fe80")


class BehaviourAnalytics:
    def __init__(self, memory=None, min_logons: int = 20, min_days: int = 3,
                 publish: Optional[Callable[[ThreatEvent], Any]] = None, clock=time.time) -> None:
        self._memory = memory
        self.min_logons = max(3, int(min_logons or 20))
        self.min_days = max(1, int(min_days or 3))
        self._publish = publish
        self._clock = clock
        self._last_alert: dict[tuple, float] = {}
        self.alerts = 0

    # ------------------------------------------------------------------ data
    @property
    def memory(self):
        if self._memory is None:
            from gates.trigate_memory import get_memory
            return get_memory()
        return self._memory

    def _profiles(self) -> dict:
        return self.memory.data.setdefault("behaviour", {})

    def profile(self, user: Any) -> Optional[dict]:
        return self._profiles().get(_norm(user))

    def learned(self, prof: Optional[dict]) -> bool:
        return bool(prof) and int(prof.get("total", 0)) >= self.min_logons \
            and len(prof.get("days", [])) >= self.min_days

    # --------------------------------------------------------------- checks
    def check(self, user: str, kind: str, ip: str, when: datetime) -> list[dict]:
        """Reasons why this logon is unusual (before it is learned)."""
        reasons: list[dict] = []
        u = _norm(user)
        prof = self.profile(u)
        total = int((prof or {}).get("total", 0))

        # 1. brand-new account already used (no learning period needed)
        try:
            age_h = self.memory.hours_since(pattern="account_created", subject=u)
        except Exception:
            age_h = None
        if age_h is not None and age_h * 60 <= NEW_ACCOUNT_MINUTES and total == 0:
            mins = max(1, int(round(age_h * 60)))
            pts = 25 if kind in ("remote", "network") else 20
            reasons.append({"kind": "new_account_used", "points": pts,
                            "text": f"Account '{u}' was created {mins} min ago and is already being used "
                                    f"({KIND_TEXT.get(kind, 'logon')})"})

        if not self.learned(prof):
            return reasons

        # 2. unusual hour
        hours = list(prof.get("hours") or [0] * 24)
        h = when.hour
        near = hours[(h - 1) % 24] + hours[h] + hours[(h + 1) % 24]
        if total and near / total < RARE_HOUR_SHARE:
            reasons.append({"kind": "unusual_hour", "points": 15,
                            "text": f"Logged on at {when:%H:%M} - '{u}' almost never logs on around this time "
                                    f"({near} of {total} logons between {(h - 1) % 24:02d}:00 and "
                                    f"{(h + 2) % 24:02d}:00)"})

        # 3. first remote / network logon
        kinds = dict(prof.get("kinds") or {})
        if kind in ("remote", "network") and not kinds.get(kind):
            usual = max(kinds, key=kinds.get) if kinds else "local"
            reasons.append({"kind": f"first_{kind}", "points": 20 if kind == "remote" else 15,
                            "text": f"First logon {KIND_TEXT[kind]} ever for '{u}' "
                                    f"(normally logs on {KIND_TEXT.get(usual, usual)})"})

        # 4. new source IP (only when the user already has known IPs)
        ips = dict(prof.get("ips") or {})
        if _is_remote_ip(ip) and ips and ip not in ips:
            reasons.append({"kind": "new_ip", "points": 10,
                            "text": f"First logon for '{u}' from IP {ip} (known: {', '.join(list(ips)[:3])})"})
        return reasons

    def learn(self, user: str, kind: str, ip: str, when: datetime) -> None:
        u = _norm(user)
        profs = self._profiles()
        prof = profs.setdefault(u, {"total": 0, "hours": [0] * 24, "kinds": {}, "ips": {},
                                    "days": [], "first": when.isoformat()})
        if len(prof.get("hours") or []) != 24:
            prof["hours"] = [0] * 24
        prof["total"] = int(prof.get("total", 0)) + 1
        prof["hours"][when.hour] += 1
        prof["kinds"][kind] = int(prof["kinds"].get(kind, 0)) + 1
        if _is_remote_ip(ip):
            prof["ips"][ip] = int(prof["ips"].get(ip, 0)) + 1
            if len(prof["ips"]) > MAX_IPS:
                for old in sorted(prof["ips"], key=prof["ips"].get)[: len(prof["ips"]) - MAX_IPS]:
                    prof["ips"].pop(old, None)
        day = when.strftime("%Y-%m-%d")
        if day not in prof["days"]:
            prof["days"] = (prof["days"] + [day])[-MAX_DAYS_KEPT:]
        prof["last"] = when.isoformat()
        try:
            self.memory._touch()
        except Exception:
            pass

    # ----------------------------------------------------------- main entry
    def observe_logon(self, user: Any, logon_type: Any, src_ip: Any = None,
                      workstation: Any = None, when: Optional[datetime] = None,
                      computer: Any = None) -> Optional[ThreatEvent]:
        """Called by the Windows ingestor for every successful logon (4624).
        Returns the ThreatEvent it published (or None)."""
        if not is_person(user):
            return None
        kind = logon_kind_of(logon_type)
        if not kind:
            return None                       # service / batch / other non-human logon
        ip = str(src_ip or "").strip()
        if kind == "network" and not _is_remote_ip(ip):
            return None                       # local network logons (this PC to itself)
        when = when or datetime.now().astimezone()
        if when.tzinfo is not None:
            when = when.astimezone()          # local time of this PC
        u = _norm(user)

        reasons = self.check(u, kind, ip, when)
        self.learn(u, kind, ip, when)
        if not reasons:
            return None

        now = self._clock()
        fresh = []
        for r in reasons:
            key = (u, r["kind"])
            if now - self._last_alert.get(key, 0) >= RATE_LIMIT_SECONDS:
                self._last_alert[key] = now
                fresh.append(r)
        if not fresh:
            return None

        score = min(1.0, sum(r["points"] for r in fresh) / 40)
        severity = Severity.HIGH if score >= 0.6 else Severity.MEDIUM
        text = "; ".join(r["text"] for r in fresh)
        event = ThreatEvent(
            source="BehaviourAnalytics",
            threat_type=ThreatType.BEHAVIORAL_ANOMALY,
            severity=severity,
            payload={
                "user_id": u,
                "entity_id": u,
                "src_ip": ip if _is_remote_ip(ip) else "",
                "logon_type": str(logon_type),
                "workstation": str(workstation or ""),
                "computer_name": str(computer or ""),
                "description": f"Unusual behaviour for '{u}': {text}"[:300],
                "behaviour_reasons": fresh,
                "behaviour_score": round(score, 2),
                "event_id_raw": None,
            },
        )
        self.alerts += 1
        log.warning("Behaviour anomaly for %s: %s", u, text)
        if self._publish is not None:
            try:
                res = self._publish(event)
                if asyncio.iscoroutine(res):
                    try:
                        asyncio.get_running_loop().create_task(res)
                    except RuntimeError:
                        asyncio.run(res)
            except Exception as exc:
                log.debug("behaviour event not published: %s", exc)
        return event

    def stats(self) -> dict:
        profs = self._profiles()
        return {"users": len(profs), "learned": sum(1 for p in profs.values() if self.learned(p)),
                "alerts": self.alerts, "min_logons": self.min_logons, "min_days": self.min_days}


_engine: Optional[BehaviourAnalytics] = None


def get_behaviour_analytics() -> Optional[BehaviourAnalytics]:
    return _engine


def configure_behaviour_analytics(enabled: Any = True, min_logons: Any = 20, min_days: Any = 3,
                                  publish=None, memory=None) -> Optional[BehaviourAnalytics]:
    global _engine
    on = str(enabled).strip().lower() not in ("false", "0", "no", "off")
    if not on:
        _engine = None
        return None
    try:
        ml = int(min_logons or 20)
    except (TypeError, ValueError):
        ml = 20
    try:
        md = int(min_days or 3)
    except (TypeError, ValueError):
        md = 3
    _engine = BehaviourAnalytics(memory=memory, min_logons=ml, min_days=md, publish=publish)
    return _engine
