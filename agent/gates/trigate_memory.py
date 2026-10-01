"""
gates/trigate_memory.py - the TriGate's long-term memory (survives restarts).

What it remembers (saved as JSON next to config.ini, file trigate_memory.json):

* events        - every TriGate decision for the last 7 days
                  (who, which attack pattern, risk) -> "history" in Gate 2
* logons        - for each user: IPs and logon types seen in SUCCESSFUL
                  logons (Windows event 4624)          -> "known PC/IP" in Gate 1
* devices       - other computers (workstation names) seen in SUCCESSFUL
                  logons                                -> device trust in Gate 1
* feedback      - "False alarm" / "Confirmed threat" clicks from the dashboard
                  per (pattern, user)                  -> learning in Gate 2
* decisions     - short map event_id -> (pattern, user) so a dashboard click
                  on a decision can find what it is about
* behaviour     - per-user logon habits learned from SUCCESSFUL logons
                  (hours, logon kinds, IPs, active days)  -> Behaviour analytics
* importance    - this PC's importance (low/normal/high/critical) when set from
                  the dashboard Endpoints page          -> Gate 3

By default the memory lives only in RAM (used by tests). The orchestrator
calls configure_memory(path) so the real agent saves to disk.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

log = logging.getLogger("TriGateMemory")

HISTORY_DAYS = 7
MAX_EVENTS = 5000
MAX_DECISIONS = 1000
MAX_USERS = 2000
MAX_IPS_PER_USER = 50
MAX_DEVICES = 500
SAVE_EVERY_SECONDS = 60

IMPORTANCE_LEVELS = ("low", "normal", "high", "critical")
FEEDBACK_KINDS = ("false_alarm", "confirmed")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse(s: Any) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(s))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _norm_user(user: Any) -> str:
    u = str(user or "").strip().lower()
    if "\\" in u:                      # DOMAIN\user -> user
        u = u.split("\\")[-1]
    if "@" in u:                       # user@domain -> user
        u = u.split("@")[0]
    return "" if u in ("", "-", "unknown", "none") else u


def _norm_device(name: Any) -> str:
    d = str(name or "").strip().lower().lstrip("\\")
    d = d.split(".")[0]                 # PC.corp.local -> pc
    return "" if d in ("", "-", "unknown", "none", "localhost", "127.0.0.1", "::1") else d


def feedback_key(pattern: str, entity: str) -> str:
    return f"{pattern}|{_norm_user(entity) or '*'}"


def normalize_importance(value: Any) -> Optional[str]:
    v = str(value or "").strip().lower()
    aliases = {"medium": "normal", "server": "high", "laptop": "normal",
               "desktop": "normal", "domain controller": "critical"}
    v = aliases.get(v, v)
    return v if v in IMPORTANCE_LEVELS else None


class TriGateMemory:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._lock = threading.RLock()
        self._dirty = False
        self._last_save = 0.0
        self.data: dict = self._empty()
        if path:
            self._load()

    # ------------------------------------------------------------------ io
    @staticmethod
    def _empty() -> dict:
        return {"version": 1, "importance": None, "events": [], "logons": {},
                "devices": {}, "feedback": {}, "decisions": {}, "behaviour": {}}

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                data = self._empty()
                for k in ("events", "logons", "devices", "feedback", "decisions", "behaviour"):
                    if isinstance(raw.get(k), type(data[k])):
                        data[k] = raw[k]
                data["importance"] = normalize_importance(raw.get("importance"))
                self.data = data
                self._prune()
                log.info("TriGate memory loaded: %d events, %d users, %d feedback entries (%s)",
                         len(data["events"]), len(data["logons"]), len(data["feedback"]), self.path)
        except Exception as exc:                       # corrupt file -> start fresh, keep a copy
            log.warning("TriGate memory file unreadable (%s) - starting fresh", exc)
            try:
                os.replace(self.path, self.path + ".bad")
            except OSError:
                pass

    def save(self, force: bool = False) -> bool:
        """Write to disk (atomic). Without force, only if changed."""
        if not self.path:
            return False
        with self._lock:
            if not (self._dirty or force):
                return False
            self._prune()
            tmp = self.path + ".tmp"
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self.data, fh, indent=1, default=str)
                os.replace(tmp, self.path)
                self._dirty = False
                self._last_save = time.monotonic()
                return True
            except OSError as exc:
                log.warning("Could not save TriGate memory: %s", exc)
                return False

    def maybe_save(self) -> None:
        """Save if changed and the last save was > SAVE_EVERY_SECONDS ago."""
        if self._dirty and time.monotonic() - self._last_save >= SAVE_EVERY_SECONDS:
            self.save()

    def _touch(self) -> None:
        self._dirty = True

    def _prune(self) -> None:
        cutoff = _now() - timedelta(days=HISTORY_DAYS)
        ev = [e for e in self.data["events"] if (_parse(e.get("ts")) or cutoff) > cutoff]
        self.data["events"] = ev[-MAX_EVENTS:]
        dec = self.data["decisions"]
        if len(dec) > MAX_DECISIONS:
            for k in list(dec)[: len(dec) - MAX_DECISIONS]:
                dec.pop(k, None)
        devs = self.data["devices"]
        if len(devs) > MAX_DEVICES:
            for d in sorted(devs, key=lambda k: devs[k].get("last_seen", ""))[: len(devs) - MAX_DEVICES]:
                devs.pop(d, None)
        beh = self.data.setdefault("behaviour", {})
        if len(beh) > MAX_USERS:
            for u in sorted(beh, key=lambda k: beh[k].get("last", ""))[: len(beh) - MAX_USERS]:
                beh.pop(u, None)
        users = self.data["logons"]
        if len(users) > MAX_USERS:
            oldest = sorted(users, key=lambda u: users[u].get("last_seen", ""))
            for u in oldest[: len(users) - MAX_USERS]:
                users.pop(u, None)

    # ------------------------------------------------------- logon context
    def record_logon(self, user: Any, src_ip: Any = None, logon_type: Any = None,
                     when: Optional[datetime] = None, workstation: Any = None) -> None:
        """Remember a SUCCESSFUL logon (event 4624): user + IP + logon type + device."""
        u = _norm_user(user)
        if not u or u.endswith("$"):          # skip computer accounts (PC$)
            return
        ts = _iso(when or _now())
        with self._lock:
            dev = _norm_device(workstation)
            if dev:
                d = self.data["devices"].setdefault(dev, {"first_seen": ts, "users": []})
                d["last_seen"] = ts
                if u not in d["users"]:
                    d["users"] = (d["users"] + [u])[-20:]
            entry = self.data["logons"].setdefault(u, {"first_seen": ts, "ips": {}, "logon_types": {}})
            entry["last_seen"] = ts
            ip = str(src_ip or "").strip()
            if ip and ip not in ("-", "unknown"):
                entry["ips"][ip] = ts
                if len(entry["ips"]) > MAX_IPS_PER_USER:
                    for old in sorted(entry["ips"], key=entry["ips"].get)[:-MAX_IPS_PER_USER]:
                        entry["ips"].pop(old, None)
            lt = str(logon_type or "").strip()
            if lt:
                entry["logon_types"][lt] = int(entry["logon_types"].get(lt, 0)) + 1
            self._touch()

    def user_known(self, user: Any) -> bool:
        return _norm_user(user) in self.data["logons"]

    def device_known(self, workstation: Any) -> bool:
        """Has this computer been used for a SUCCESSFUL logon here before?"""
        return _norm_device(workstation) in self.data["devices"]

    def ip_known_for_user(self, user: Any, ip: Any) -> bool:
        entry = self.data["logons"].get(_norm_user(user))
        return bool(entry) and str(ip or "").strip() in entry.get("ips", {})

    # ------------------------------------------------------------ history
    def record_event(self, event_id: str, entity: Any, pattern: str, risk: int,
                     subject: Any = None, when: Optional[datetime] = None) -> None:
        ts = _iso(when or _now())
        with self._lock:
            self.data["events"].append({
                "ts": ts, "event_id": event_id, "entity": _norm_user(entity),
                "subject": _norm_user(subject), "pattern": pattern, "risk": int(risk),
            })
            self.data["decisions"][event_id] = {
                "pattern": pattern, "entity": _norm_user(entity), "ts": ts}
            if len(self.data["events"]) > MAX_EVENTS * 1.2:
                self._prune()
            self._touch()

    def count_events(self, *, entity: Any = None, pattern: Optional[str] = None,
                     subject: Any = None, hours: float = 24, exclude_event: Optional[str] = None) -> int:
        cutoff = _now() - timedelta(hours=hours)
        ent, sub = _norm_user(entity), _norm_user(subject)
        n = 0
        for e in self.data["events"]:
            if exclude_event and e.get("event_id") == exclude_event:
                continue
            ts = _parse(e.get("ts"))
            if not ts or ts < cutoff:
                continue
            if entity is not None and e.get("entity") != ent:
                continue
            if subject is not None and sub not in (e.get("subject"), e.get("entity")):
                continue
            if pattern and e.get("pattern") != pattern:
                continue
            n += 1
        return n

    def hours_since(self, *, pattern: str, subject: Any) -> Optional[float]:
        """Hours since `pattern` last happened to `subject` (e.g. account created)."""
        sub = _norm_user(subject)
        if not sub:
            return None
        best = None
        for e in self.data["events"]:
            if e.get("pattern") == pattern and sub in (e.get("subject"), e.get("entity")):
                ts = _parse(e.get("ts"))
                if ts and (best is None or ts > best):
                    best = ts
        if best is None:
            return None
        return max(0.0, (_now() - best).total_seconds() / 3600)

    # ----------------------------------------------------------- feedback
    def add_feedback(self, kind: str, *, event_id: Optional[str] = None,
                     pattern: Optional[str] = None, entity: Any = None) -> dict:
        """Record analyst feedback. Returns the updated counters."""
        if kind not in FEEDBACK_KINDS:
            raise ValueError(f"feedback must be one of {FEEDBACK_KINDS}")
        if event_id and not pattern:
            d = self.data["decisions"].get(event_id)
            if not d:
                raise KeyError(f"unknown decision {event_id!r} (older than memory or from another PC)")
            pattern, entity = d["pattern"], d["entity"]
        if not pattern:
            raise ValueError("pattern or event_id is required")
        key = feedback_key(pattern, entity)
        with self._lock:
            fb = self.data["feedback"].setdefault(key, {"false_alarm": 0, "confirmed": 0})
            fb[kind] = int(fb.get(kind, 0)) + 1
            fb["last"] = _iso(_now())
            self._touch()
        self.save(force=True)                   # feedback is precious: save now
        return {"key": key, "pattern": pattern, "entity": _norm_user(entity), **fb}

    def feedback_for(self, pattern: str, entity: Any) -> dict:
        """Counters for this user+pattern (falls back to the pattern for any user)."""
        fb = self.data["feedback"].get(feedback_key(pattern, entity))
        if fb is None:
            fb = self.data["feedback"].get(feedback_key(pattern, None))
        return {"false_alarm": int((fb or {}).get("false_alarm", 0)),
                "confirmed": int((fb or {}).get("confirmed", 0))}

    # --------------------------------------------------------- importance
    def get_importance(self) -> Optional[str]:
        return normalize_importance(self.data.get("importance"))

    def set_importance(self, value: Any) -> str:
        imp = normalize_importance(value)
        if not imp:
            raise ValueError(f"importance must be one of {IMPORTANCE_LEVELS}")
        with self._lock:
            self.data["importance"] = imp
            self._touch()
        self.save(force=True)
        return imp

    def stats(self) -> dict:
        return {"events": len(self.data["events"]), "users": len(self.data["logons"]),
                "devices": len(self.data["devices"]), "feedback": len(self.data["feedback"]),
                "path": self.path}


_memory: Optional[TriGateMemory] = None


def get_memory() -> TriGateMemory:
    """The shared memory (RAM-only until configure_memory() is called)."""
    global _memory
    if _memory is None:
        _memory = TriGateMemory(None)
    return _memory


def configure_memory(path: Optional[str]) -> TriGateMemory:
    """Use a disk-backed memory at `path` (called once by the orchestrator)."""
    global _memory
    _memory = TriGateMemory(path)
    return _memory


def set_memory(mem: TriGateMemory) -> None:
    """Tests: swap in a specific memory object."""
    global _memory
    _memory = mem
