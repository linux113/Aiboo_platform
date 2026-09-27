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
    print("Warning: pywin32 not installed. Windows Event Log ingestion disabled.")

from core.event_bus import EventBus
from core.events import ThreatEvent, ThreatType, Severity

log = logging.getLogger("WindowsIngestor")


# ============================================================
# Rule loading (YAML-based, no more hardcoded dicts)
# ============================================================

# Safe fallback rules — used only if YAML fails to load
_FALLBACK_RULES = {
    4625: (ThreatType.IDENTITY_MISMATCH, Severity.HIGH),
    1102: (ThreatType.ANOMALOUS_BEHAVIOR, Severity.CRITICAL),
}

_FALLBACK_CHANNELS = ["Security", "System", "Application"]


def _resolve_config_path() -> str:
    """
    Resolve path to config/event_rules.yaml — works both when running
    as a script and when bundled as a PyInstaller .exe.
    """
    # PyInstaller: sys.executable is the .exe path
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        # Running from source: this file is at agent/log_ingestion/windows_ingestor.py
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Try a few common locations
    candidates = [
        os.path.join(base, "config", "event_rules.yaml"),
        os.path.join(base, "event_rules.yaml"),
        os.path.join(os.getcwd(), "config", "event_rules.yaml"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]  # return first even if missing, for logging


def _load_rules_from_yaml():
    """
    Load event ID mapping and log channels from config/event_rules.yaml.
    Returns (mapping_dict, channels_list, source_label).
    """
    if not YAML_AVAILABLE:
        log.warning("pyyaml not available — using fallback rules")
        return _FALLBACK_RULES, _FALLBACK_CHANNELS, "fallback (no pyyaml)"

    config_path = _resolve_config_path()
    if not os.path.exists(config_path):
        log.warning(f"Rules file not found at {config_path} — using fallback rules")
        return _FALLBACK_RULES, _FALLBACK_CHANNELS, "fallback (no file)"

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Build event_id -> (ThreatType, Severity) mapping
        mapping = {}
        for rule in data.get("rules", []):
            try:
                event_id = int(rule["event_id"])
                threat_type = ThreatType(rule["threat_type"])
                severity = Severity(rule["severity"])
                mapping[event_id] = (threat_type, severity)
            except (KeyError, ValueError) as e:
                log.warning(f"Skipping invalid rule {rule}: {e}")

        channels = data.get("channels", _FALLBACK_CHANNELS)
        if not mapping:
            log.warning("YAML loaded but no valid rules found — using fallback")
            return _FALLBACK_RULES, channels, "fallback (empty yaml)"

        log.info(f"Loaded {len(mapping)} event rules from {config_path}")
        return mapping, channels, config_path

    except Exception as e:
        log.error(f"Failed to load rules from {config_path}: {e}")
        return _FALLBACK_RULES, _FALLBACK_CHANNELS, "fallback (parse error)"


# Load rules at import time
EVENT_ID_MAPPING, DEFAULT_CHANNELS, RULES_SOURCE = _load_rules_from_yaml()


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
    def __init__(
        self,
        bus: EventBus,
        log_names: list[str] = None,
        min_severity: Severity = Severity.HIGH,
    ):
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("win32evtlog not available. Install pywin32.")

        self.bus = bus
        self.log_names = log_names or DEFAULT_CHANNELS
        self.min_severity = min_severity
        self._running = False
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._baseline = BaselineStats()

        log.info(
            "WindowsEventIngestor initialized — %d rules loaded from %s",
            len(EVENT_ID_MAPPING),
            RULES_SOURCE,
        )
        log.info("Monitoring %d log channels: %s", len(self.log_names), self.log_names)

    async def start(self, tail_only: bool = True):
        log.info(f"Starting Windows Event Log ingestion from: {self.log_names}")
        self._running = True

        poll_thread = threading.Thread(
            target=self._poll_events,
            args=(tail_only,),
            daemon=True,
        )
        poll_thread.start()

        await self._process_events()

    def _poll_events(self, tail_only: bool):
        for log_name in self.log_names:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while self._running:
                    try:
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                    except Exception as read_err:
                        log.debug(f"Read error on {log_name}: {read_err}")
                        break

                    for event in events:
                        try:
                            self._event_queue.put((log_name, event), timeout=1)
                        except queue.Full:
                            log.warning(f"Event queue full — dropping event from {log_name}")

                    threading.Event().wait(0.5)

            except Exception as e:
                log.error(f"Failed to read log {log_name}: {e}")

    async def _process_events(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                log_name, event = await loop.run_in_executor(
                    None, self._event_queue.get, True, 0.1
                )
                threat_event = self._normalize_event(log_name, event)
                if threat_event and threat_event.severity.weight >= self.min_severity.weight:
                    self._baseline.update(threat_event.threat_type.value, threat_event.timestamp)
                    await self.bus.publish(threat_event)
            except queue.Empty:
                await asyncio.sleep(0.1)
            except Exception as e:
                log.error(f"Error processing event: {e}")

    def _normalize_event(self, log_name: str, event) -> Optional[ThreatEvent]:
        try:
            event_id = event.EventID
            threat_type, severity = EVENT_ID_MAPPING.get(
                event_id, (ThreatType.ANOMALOUS_BEHAVIOR, Severity.MEDIUM)
            )

            strings = event.StringInserts or []

            # ---- Base payload with standardised CSDE fields ----
            payload = {
                "event_id_raw": event_id,
                "log_name": log_name,
                "computer_name": event.ComputerName,
                "time_generated": event.TimeGenerated.isoformat(),
                "timestamp": event.TimeGenerated.isoformat(),
                "strings": strings,
                "user_id": "unknown",
                "entity_id": "unknown",
                "src_ip": "unknown",
                "location": "",
                "detected_location": "",
                "claimed_location": "",
                "device_id": "",
                "anomaly_score": 0.0,
            }

            # ---- Field extraction by event ID ----
            if event_id == 4625:  # Failed logon
                user_id = strings[5] if len(strings) > 5 else "unknown"
                src_ip = strings[18] if len(strings) > 18 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "src_ip": src_ip,
                    "failure_reason": strings[2] if len(strings) > 2 else "unknown",
                })
            elif event_id == 4624:  # Successful logon
                user_id = strings[5] if len(strings) > 5 else "unknown"
                src_ip = strings[18] if len(strings) > 18 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "src_ip": src_ip,
                })
            elif event_id == 4648:  # Explicit credentials (RunAs)
                user_id = strings[5] if len(strings) > 5 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                })
            elif event_id == 4672:  # Admin logon
                user_id = strings[1] if len(strings) > 1 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                })
            elif event_id == 4688:  # Process creation
                user_id = strings[4] if len(strings) > 4 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "process_name": strings[5] if len(strings) > 5 else "unknown",
                    "command_line": strings[7] if len(strings) > 7 else "unknown",
                })
            elif event_id in (4673, 4674):  # Privilege escalation
                user_id = strings[0] if len(strings) > 0 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "privilege": strings[2] if len(strings) > 2 else "unknown",
                })
            elif event_id == 1102:  # Audit log cleared
                user_id = strings[1] if len(strings) > 1 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "severity_reason": "audit_log_cleared",
                })
            elif event_id == 4720:  # User account created
                user_id = strings[0] if len(strings) > 0 else "unknown"
                target_user = strings[1] if len(strings) > 1 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "target_user": target_user,
                })
            elif event_id == 5140:  # Network share accessed
                user_id = strings[6] if len(strings) > 6 else "unknown"
                share_name = strings[1] if len(strings) > 1 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "share_name": share_name,
                })
            elif event_id == 4768:  # Kerberos TGT
                user_id = strings[0] if len(strings) > 0 else "unknown"
                src_ip = strings[9] if len(strings) > 9 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "src_ip": src_ip,
                })
            elif event_id == 4769:  # Kerberos service ticket
                user_id = strings[0] if len(strings) > 0 else "unknown"
                src_ip = strings[6] if len(strings) > 6 else "unknown"
                payload.update({
                    "user_id": user_id,
                    "entity_id": user_id,
                    "src_ip": src_ip,
                })
            elif event_id == 7045:  # System log — new service
                service_name = strings[0] if len(strings) > 0 else "unknown"
                payload.update({
                    "service_name": service_name,
                    "entity_id": "system",
                    "user_id": "system",
                })
            else:
                # Generic fallback: try to get user from strings[0]
                if strings and strings[0]:
                    user_id = strings[0]
                    if user_id and user_id != "unknown":
                        payload["user_id"] = user_id
                        payload["entity_id"] = user_id

            # Ensure entity_id is always set
            if payload["entity_id"] == "unknown" and payload["user_id"] != "unknown":
                payload["entity_id"] = payload["user_id"]

            # Compute anomaly score
            anomaly_score = self._calculate_anomaly_score(threat_type.value)
            payload["anomaly_score"] = anomaly_score

            return ThreatEvent(
                source=f"windows_event_log:{log_name}",
                threat_type=threat_type,
                severity=severity,
                payload=payload,
                timestamp=event.TimeGenerated,
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
        log.info("Windows Event Ingestor stopped")