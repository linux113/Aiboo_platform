"""
Real Windows Event Log ingestor using win32evtlog
Handles messy data, partial fields, and streaming

Enhanced for Cyber‑Physical Convergence – now emits standardised fields:
user_id, entity_id, src_ip, timestamp, location (placeholder), and device_id.
"""

from __future__ import annotations
import asyncio
import logging
import threading
import queue
from datetime import datetime, timedelta
from typing import Any, Optional
from dataclasses import dataclass, field
from collections import deque

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

# Event ID to Threat Type mapping (real Windows events)
EVENT_ID_MAPPING = {
    # Network/Connection events
    5156: (ThreatType.NETWORK_INTRUSION, Severity.MEDIUM),
    5157: (ThreatType.NETWORK_INTRUSION, Severity.HIGH),
    5158: (ThreatType.NETWORK_INTRUSION, Severity.MEDIUM),
    
    # Authentication/Identity events
    4624: (ThreatType.IDENTITY_MISMATCH, Severity.LOW),
    4625: (ThreatType.IDENTITY_MISMATCH, Severity.HIGH),
    4648: (ThreatType.IDENTITY_MISMATCH, Severity.MEDIUM),
    4672: (ThreatType.IDENTITY_MISMATCH, Severity.HIGH),
    
    # Process creation (potential malware)
    4688: (ThreatType.ANOMALOUS_BEHAVIOR, Severity.MEDIUM),
    4689: (ThreatType.ANOMALOUS_BEHAVIOR, Severity.LOW),
    
    # Privilege escalation
    4673: (ThreatType.INSIDER_THREAT, Severity.HIGH),
    4674: (ThreatType.INSIDER_THREAT, Severity.HIGH),
    
    # File/Data access
    4663: (ThreatType.INSIDER_THREAT, Severity.MEDIUM),
    4656: (ThreatType.INSIDER_THREAT, Severity.MEDIUM),
}

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
    def __init__(self, bus: EventBus, log_names: list[str] = None, min_severity: Severity = Severity.HIGH):
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("win32evtlog not available. Install pywin32.")
        
        self.bus = bus
        self.log_names = log_names or ["Security", "System", "Application"]
        self.min_severity = min_severity
        self._running = False
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._baseline = BaselineStats()
        
    async def start(self, tail_only: bool = True):
        log.info(f"Starting Windows Event Log ingestion from: {self.log_names}")
        self._running = True
        
        poll_thread = threading.Thread(
            target=self._poll_events,
            args=(tail_only,),
            daemon=True
        )
        poll_thread.start()
        
        await self._process_events()
    
    def _poll_events(self, tail_only: bool):
        for log_name in self.log_names:
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while self._running:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    for event in events:
                        self._event_queue.put((log_name, event))
                    threading.Event().wait(0.5)
                    
            except Exception as e:
                log.error(f"Failed to read log {log_name}: {e}")
    
    async def _process_events(self):
        while self._running:
            try:
                log_name, event = await asyncio.get_event_loop().run_in_executor(
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
                "timestamp": event.TimeGenerated.isoformat(),   # alias for CSDE
                "strings": strings,
                # ---- CSDE standard fields (will be updated below) ----
                "user_id": "unknown",
                "entity_id": "unknown",
                "src_ip": "unknown",
                "location": "",
                "detected_location": "",
                "claimed_location": "",
                "device_id": "",
                "anomaly_score": 0.0,
            }
            
            # Extract common fields for specific event types
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
            elif event_id == 4688:  # Process creation
                # strings[4] often contains the user who started the process
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
                timestamp=event.TimeGenerated  # use actual event time
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