"""
Real Windows Event Log ingestor using win32evtlog
Handles messy data, partial fields, and streaming

Enhanced for Cyber‑Physical Convergence – now emits standardised fields:
user_id, entity_id, src_ip, timestamp, location (placeholder), and device_id.

NEW: Event rules are loaded from config/event_rules.yaml (not hardcoded).
     No rebuild needed to add new event IDs — just edit the YAML file.
"""

from __future__ import annotations
import asyncio
import logging
import threading
import queue
import os
import sys
from datetime import datetime, timedelta
from typing import Any, Optional
from dataclasses import dataclass, field
from collections import deque

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: pyyaml not installed. Falling back to defaults. Run: pip install pyyaml")

try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import pywintypes
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    # Not on Windows (or pywin32 missing): the ingestor logs a warning and stays idle.

from core.event_bus import EventBus
from core.events import ThreatEvent, ThreatType, Severity
from log_ingestion.windows_event_parser import (
    BRUTE_FORCE_EVENT_IDS, BruteForceTracker, extract_fields, should_drop, task_is_suspicious,
)

log = logging.getLogger("WindowsIngestor")


# ============================================================
# Rule loading (YAML-based, no more hardcoded dicts)
# ============================================================

# Safe fallback rules — used only if YAML fails to load.
# Keys are (channel, event_id): an event ID only means something inside its
# own log (e.g. ID 1102 in the Application log is NOT "audit log cleared").
_FALLBACK_RULES = {
    ("Security", 4625): (ThreatType.IDENTITY_MISMATCH, Severity.MEDIUM),
    ("Security", 4740): (ThreatType.IDENTITY_MISMATCH, Severity.HIGH),
    ("Security", 1102): (ThreatType.ANOMALOUS_BEHAVIOR, Severity.CRITICAL),
}

_FALLBACK_CHANNELS = ["Security", "System"]

# Default channel for a rule that does not name one
_SYSTEM_LOG_EVENT_IDS = {7045, 7040, 7036, 104}

_DEFAULT_SETTINGS = {
    "brute_force_threshold": 5,
    "brute_force_window_seconds": 300,
    "max_events_per_poll": 2000,
    "poll_interval_seconds": 2.0,
}


def _resolve_config_path() -> str:
    """
    Resolve path to config/event_rules.yaml — works both when running
    as a script and when bundled as a PyInstaller .exe.
    """
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(base, "config", "event_rules.yaml"),
        os.path.join(base, "event_rules.yaml"),
        os.path.join(os.getcwd(), "config", "event_rules.yaml"),
    ]
    bundled = getattr(sys, "_MEIPASS", None)      # copy packed inside the .exe
    if bundled:
        candidates.append(os.path.join(bundled, "config", "event_rules.yaml"))
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]


def _default_channel(event_id: int) -> str:
    return "System" if event_id in _SYSTEM_LOG_EVENT_IDS else "Security"


def parse_rules(data: dict):
    """
    Parse the YAML structure into (mapping, channels, settings).
    Split out from file loading so it can be unit-tested.
    """
    mapping = {}
    for rule in (data or {}).get("rules", []) or []:
        try:
            event_id = int(rule["event_id"])
            channel = str(rule.get("channel") or _default_channel(event_id))
            threat_type = ThreatType(rule["threat_type"])
            severity = Severity(rule["severity"])
            mapping[(channel.lower(), event_id)] = (threat_type, severity)
        except (KeyError, ValueError, TypeError) as e:
            log.warning(f"Skipping invalid rule {rule}: {e}")

    channels = (data or {}).get("channels") or list(_FALLBACK_CHANNELS)
    settings = dict(_DEFAULT_SETTINGS)
    bf = (data or {}).get("brute_force") or {}
    if isinstance(bf, dict):
        if "threshold" in bf:
            settings["brute_force_threshold"] = int(bf["threshold"])
        if "window_seconds" in bf:
            settings["brute_force_window_seconds"] = int(bf["window_seconds"])
    return mapping, channels, settings


def _fallback():
    return ({(c.lower(), e): v for (c, e), v in _FALLBACK_RULES.items()},
            list(_FALLBACK_CHANNELS), dict(_DEFAULT_SETTINGS))


def _load_rules_from_yaml():
    """
    Load event rules, channels and settings from config/event_rules.yaml.
    Returns (mapping, channels, settings, source_label).
    """
    if not YAML_AVAILABLE:
        log.warning("pyyaml not available — using fallback rules")
        return (*_fallback(), "fallback (no pyyaml)")

    config_path = _resolve_config_path()
    if not os.path.exists(config_path):
        log.warning(f"Rules file not found at {config_path} — using fallback rules")
        return (*_fallback(), "fallback (no file)")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        mapping, channels, settings = parse_rules(data)
        if not mapping:
            log.warning("YAML loaded but no valid rules found — using fallback")
            fb_map, _, _ = _fallback()
            return fb_map, channels, settings, "fallback (empty yaml)"
        log.info(f"Loaded {len(mapping)} event rules from {config_path}")
        return mapping, channels, settings, config_path
    except Exception as e:
        log.error(f"Failed to load rules from {config_path}: {e}")
        return (*_fallback(), "fallback (parse error)")


# Load rules at import time
EVENT_ID_MAPPING, DEFAULT_CHANNELS, INGEST_SETTINGS, RULES_SOURCE = _load_rules_from_yaml()


SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class BaselineStats:
    """Statistical baseline for anomaly detection"""
    event_rates: dict[str, deque] = field(default_factory=dict)
    mean_rates: dict[str, float] = field(default_factory=dict)
    std_rates: dict[str, float] = field(default_factory=dict)

    def update(self, event_type: str, timestamp: datetime, window_minutes: int = 10):
        if event_type not in self.event_rates:
            self.event_rates[event_type] = deque(maxlen=1000)

        minute_key = timestamp.replace(second=0, microsecond=0)
        self.event_rates[event_type].append(minute_key)

        cutoff = timestamp - timedelta(minutes=window_minutes)
        while self.event_rates[event_type] and self.event_rates[event_type][0] < cutoff:
            self.event_rates[event_type].popleft()

        if len(self.event_rates[event_type]) > 10:
            rates = [1] * len(self.event_rates[event_type])
            self.mean_rates[event_type] = sum(rates) / len(rates)
            variance = sum((r - self.mean_rates[event_type]) ** 2 for r in rates) / len(rates)
            self.std_rates[event_type] = variance ** 0.5


class WindowsEventIngestor:
    """
    Tails the classic Windows event logs (Security, System, ...).

    At start-up it remembers the newest record number in each log and from
    then on only reads records that arrive AFTER that — old history is
    never replayed. Every poll cycle visits every channel in turn.
    """

    def __init__(
        self,
        bus: EventBus,
        log_names: list[str] = None,
        min_severity: Severity = Severity.HIGH,
        rules: Optional[dict] = None,
        settings: Optional[dict] = None,
    ):
        self.bus = bus
        self.log_names = list(log_names or DEFAULT_CHANNELS)
        self.min_severity = min_severity
        self.rules = rules if rules is not None else EVENT_ID_MAPPING
        self.settings = {**_DEFAULT_SETTINGS, **INGEST_SETTINGS, **(settings or {})}
        self._running = False
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._baseline = BaselineStats()
        self._brute_force = BruteForceTracker(
            threshold=self.settings["brute_force_threshold"],
            window_seconds=self.settings["brute_force_window_seconds"],
        )
        self._stats = {"read": 0, "published": 0, "dropped_noise": 0}

        if not WINDOWS_AVAILABLE:
            log.warning("pywin32 not available — Windows Event Log ingestion disabled on this OS.")
            return

        log.info(
            "WindowsEventIngestor initialized — %d rules loaded from %s",
            len(self.rules), RULES_SOURCE,
        )

    @staticmethod
    def logon_failure_auditing(auditpol_output: str) -> Optional[bool]:
        """
        Parse `auditpol /get /subcategory:{Logon GUID}` output.
        True/False when we can tell, None when the output is unreadable
        (e.g. non-English Windows).
        """
        for line in (auditpol_output or "").splitlines():
            low = line.strip().lower()
            if not low.startswith("logon") or low.startswith("logoff"):
                continue
            if "failure" in low:
                return True
            if "success" in low or "no auditing" in low:
                return False
        return None

    def _check_logon_auditing(self) -> None:
        """Warn when Windows is not recording failed logons (event 4625)."""
        import subprocess
        try:
            out = subprocess.run(
                ["auditpol", "/get", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}"],
                capture_output=True, text=True, timeout=10,
            ).stdout
        except Exception as e:
            log.debug("auditpol check skipped: %s", e)
            return
        state = self.logon_failure_auditing(out)
        if state is False:
            log.warning(
                "Windows is NOT recording failed logons (Audit Logon: Failure is off), "
                "so wrong-password / brute-force alerts cannot work. Fix (Administrator): "
                'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
            )
        elif state is True:
            log.info("Failed-logon auditing is ON (event 4625 will be recorded)")

    async def start(self, tail_only: bool = True):
        if not WINDOWS_AVAILABLE:
            log.warning("Windows Event Log ingestion skipped (not running on Windows / no pywin32).")
            return
        log.info(f"Starting Windows Event Log ingestion from: {self.log_names}")
        self._check_logon_auditing()
        self._running = True

        poll_thread = threading.Thread(
            target=self._poll_events,
            args=(tail_only,),
            daemon=True,
        )
        poll_thread.start()

        await self._process_events()

    # ------------------------------------------------------------------
    # Reading (runs in a background thread)
    # ------------------------------------------------------------------

    @staticmethod
    def _newest_record(log_name: str) -> int:
        hand = win32evtlog.OpenEventLog(None, log_name)
        try:
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            return (oldest + total - 1) if total else 0
        finally:
            win32evtlog.CloseEventLog(hand)

    def _read_new_records(self, log_name: str, last_seen: int) -> tuple[list, int]:
        """
        Return (records newer than last_seen in chronological order, new last_seen).
        Reads backwards from the newest record and stops at last_seen.
        """
        newest = self._newest_record(log_name)
        if newest == last_seen:
            return [], last_seen
        if newest < last_seen:
            # Log was cleared (record numbers restarted): read what's there now
            log.warning("Event log %s was cleared or wrapped — resyncing", log_name)
            last_seen = 0

        limit = int(self.settings["max_events_per_poll"])
        collected = []
        hand = win32evtlog.OpenEventLog(None, log_name)
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            done = False
            while not done:
                batch = win32evtlog.ReadEventLog(hand, flags, 0)
                if not batch:
                    break
                for ev in batch:
                    if ev.RecordNumber <= last_seen:
                        done = True
                        break
                    collected.append(ev)
                    if len(collected) >= limit:
                        log.warning("More than %d new events in %s — skipping older ones", limit, log_name)
                        done = True
                        break
        finally:
            win32evtlog.CloseEventLog(hand)

        if collected:
            last_seen = max(last_seen, max(ev.RecordNumber for ev in collected))
        collected.reverse()
        return collected, last_seen

    def _poll_events(self, tail_only: bool):
        last_seen: dict[str, int] = {}
        for name in self.log_names:
            if "/" in name:
                # Modern channels (Microsoft-Windows-.../Operational) cannot be
                # opened with the classic OpenEventLog API.
                log.info("Skipping channel '%s' (not readable with the classic event log API)", name)
                continue
            try:
                last_seen[name] = self._newest_record(name) if tail_only else 0
                log.info("Watching '%s' for new events (starting after record %d)", name, last_seen[name])
            except Exception as e:
                hint = " — run the agent as Administrator to read the Security log" \
                    if name.lower() == "security" else ""
                log.error("Cannot open event log '%s': %s%s", name, e, hint)

        if not last_seen:
            log.error("No Windows event logs could be opened — ingestion idle.")
            return

        interval = float(self.settings["poll_interval_seconds"])
        error_logged: set[str] = set()
        stop = threading.Event()
        while self._running:
            for name in list(last_seen):
                try:
                    records, last_seen[name] = self._read_new_records(name, last_seen[name])
                    error_logged.discard(name)
                except Exception as e:
                    if name not in error_logged:
                        log.warning("Read error on '%s': %s", name, e)
                        error_logged.add(name)
                    continue
                for ev in records:
                    try:
                        self._event_queue.put((name, ev), timeout=1)
                    except queue.Full:
                        log.warning("Event queue full — dropping event from %s", name)
            stop.wait(interval)

    # ------------------------------------------------------------------
    # Processing (async)
    # ------------------------------------------------------------------

    async def _process_events(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                log_name, event = await loop.run_in_executor(
                    None, self._event_queue.get, True, 0.5
                )
            except queue.Empty:
                continue
            try:
                self._stats["read"] += 1
                threat_event = self._normalize_event(log_name, event)
                if threat_event is None:
                    continue
                threat_event = self._apply_brute_force(threat_event)
                self._remember_context(threat_event)
                behaviour_event = self._check_behaviour(threat_event)
                if behaviour_event is not None:
                    await self.bus.publish(behaviour_event)
                if threat_event.severity.weight >= self.min_severity.weight:
                    self._baseline.update(threat_event.threat_type.value, threat_event.timestamp)
                    self._stats["published"] += 1
                    log.info("Windows event %s -> %s: %s",
                             threat_event.payload.get("event_id_raw"),
                             threat_event.severity.value,
                             threat_event.payload.get("description"))
                    await self.bus.publish(threat_event)
            except Exception as e:
                log.error(f"Error processing event: {e}")

    @staticmethod
    def _remember_context(threat_event: ThreatEvent) -> None:
        """TriGate Gate 1 context: remember SUCCESSFUL logons (4624) - which
        user logged in from which IP / logon type - so later events can be
        judged against "known" behaviour. 4624 is LOW severity and never
        published, so this must happen before the severity filter."""
        p = threat_event.payload
        if p.get("event_id_raw") != 4624:
            return
        try:
            from gates.trigate_memory import get_memory
            ts = threat_event.timestamp if isinstance(threat_event.timestamp, datetime) else None
            if ts is not None and ts.tzinfo is None:
                ts = ts.astimezone()          # naive Windows time is local time
            get_memory().record_logon(p.get("user_id"), p.get("src_ip"), p.get("logon_type"), ts,
                                      workstation=p.get("workstation"))
        except Exception as exc:              # memory must never break ingestion
            log.debug("TriGate context not recorded: %s", exc)

    @staticmethod
    def _check_behaviour(threat_event: ThreatEvent):
        """Behaviour analytics: learn this user's logon habits from every
        SUCCESSFUL logon (4624) and return a BEHAVIORAL_ANOMALY event when the
        logon does not fit (new account in use, unusual hour, first RDP...)."""
        p = threat_event.payload
        if p.get("event_id_raw") != 4624:
            return None
        try:
            from engines.behaviour_analytics import get_behaviour_analytics
            engine = get_behaviour_analytics()
            if engine is None:
                return None
            ts = threat_event.timestamp if isinstance(threat_event.timestamp, datetime) else None
            if ts is not None and ts.tzinfo is None:
                ts = ts.astimezone()
            return engine.observe_logon(p.get("user_id"), p.get("logon_type"), p.get("src_ip"),
                                        workstation=p.get("workstation"), when=ts,
                                        computer=p.get("computer_name"))
        except Exception as exc:              # analytics must never break ingestion
            log.debug("Behaviour analytics skipped: %s", exc)
            return None

    def _apply_brute_force(self, threat_event: ThreatEvent) -> ThreatEvent:
        """Escalate repeated failed logons (same user or IP) to one HIGH alert."""
        p = threat_event.payload
        if p.get("event_id_raw") not in BRUTE_FORCE_EVENT_IDS:
            return threat_event
        if p.get("event_id_raw") == 4776 and not p.get("failure_reason"):
            return threat_event
        ts = threat_event.timestamp if isinstance(threat_event.timestamp, datetime) else datetime.now()
        hit = self._brute_force.record(p, ts.replace(tzinfo=None))
        if not hit:
            return threat_event
        window_min = max(int(self.settings["brute_force_window_seconds"]) // 60, 1)
        who = f"user '{hit['key']}'" if hit["kind"] == "user" else f"IP {hit['key']}"
        p["brute_force"] = True
        p["failed_attempts"] = hit["count"]
        p["description"] = (
            f"Possible password guessing: {hit['count']} failed logons for {who} "
            f"in {window_min} min (last: {p.get('failure_reason', 'unknown reason')}"
            + (f", from {p['src_ip']}" if p.get("src_ip") not in (None, "", "unknown") else "")
            + ")"
        )
        if threat_event.severity.weight < Severity.HIGH.weight:
            threat_event.severity = Severity.HIGH
        return threat_event

    def _normalize_event(self, log_name: str, event) -> Optional[ThreatEvent]:
        try:
            # Classic API returns the full 32-bit ID (qualifiers in the high
            # word, e.g. 7045 arrives as 0x40001B85) — keep the real ID.
            event_id = int(event.EventID) & 0xFFFF
            rule = self.rules.get((log_name.lower(), event_id))
            if rule is None:
                return None  # not a rule we watch in this channel
            threat_type, severity = rule

            strings = list(event.StringInserts or [])
            fields = extract_fields(event_id, strings)
            if should_drop(event_id, fields):
                self._stats["dropped_noise"] += 1
                return None

            # A new scheduled task is only interesting if it runs something
            # script-like; updaters register harmless tasks all the time.
            if event_id == 4698 and not task_is_suspicious(fields.get("task_command", "")):
                severity = Severity.MEDIUM

            # "added to group Users / None" is a routine side effect of creating
            # an account; only privileged groups (Administrators, RDP, ...) matter.
            if event_id in (4728, 4732, 4756) and not fields.get("privileged_group"):
                severity = Severity.LOW

            ts = event.TimeGenerated
            payload = {
                "event_id_raw": event_id,
                "record_number": getattr(event, "RecordNumber", None),
                "log_name": log_name,
                "computer_name": event.ComputerName,
                "time_generated": ts.isoformat(),
                "timestamp": ts.isoformat(),
                "strings": strings[:25],
                "user_id": "unknown",
                "entity_id": "unknown",
                "src_ip": "unknown",
                "location": "",
                "detected_location": "",
                "claimed_location": "",
                "device_id": event.ComputerName or "",
                "anomaly_score": 0.0,
                "windows_event": True,
            }
            payload.update(fields)
            if not payload.get("description"):
                payload["description"] = f"Windows event {event_id} in the {log_name} log"
            if payload.get("user_id") in (None, "", "-"):
                payload["user_id"] = "unknown"
            payload["entity_id"] = payload["user_id"] if payload["user_id"] != "unknown" \
                else (payload.get("device_id") or "unknown")
            payload["anomaly_score"] = self._calculate_anomaly_score(threat_type.value)

            return ThreatEvent(
                source=f"windows_event_log:{log_name}",
                threat_type=threat_type,
                severity=severity,
                payload=payload,
                timestamp=ts,
            )
        except Exception as e:
            log.debug(f"Failed to normalize event: {e}")
            return None

    def _calculate_anomaly_score(self, event_type: str) -> float:
        if event_type not in self._baseline.mean_rates:
            return 0.0
        mean = self._baseline.mean_rates.get(event_type, 0)
        std = self._baseline.std_rates.get(event_type, 1)
        if std == 0:
            return 0.0
        return abs((1 - mean) / std)

    async def stop(self):
        self._running = False
        log.info("Windows Event Ingestor stopped (read=%d, published=%d, noise dropped=%d)",
                 self._stats["read"], self._stats["published"], self._stats["dropped_noise"])
