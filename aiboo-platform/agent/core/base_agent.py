"""core/base_agent.py — Abstract base class for all AiBoO specialist agents."""
from __future__ import annotations
import logging
import hashlib
import json
from collections import deque
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from .event_bus import EventBus
from .events import AgentFinding, ThreatEvent


class BaseAgent(ABC):
    def __init__(self, name: str, bus: EventBus) -> None:
        self.name = name
        self.bus  = bus
        self.log  = logging.getLogger(name)
        # Fingerprint cache to deduplicate events with same logical content
        self._recent_fingerprints = deque(maxlen=200)
        self._fingerprint_ttl = 60  # seconds

    def register(self) -> None:
        self.bus.subscribe(ThreatEvent, self._handle)
        self.log.info("Registered and listening.")

    def _get_fingerprint(self, event: ThreatEvent) -> str:
        """Generate a fingerprint based on event content, ignoring timestamp and event_id."""
        p = event.payload
        # Build a canonical representation of the event's logical identity
        # Exclude 'timestamp' and 'event_id' from the payload if present
        payload_copy = {k: v for k, v in p.items() if k not in ('timestamp', 'event_id', 'time_generated')}
        # Sort keys for deterministic ordering
        canonical = {
            'threat_type': event.threat_type.value,
            'source': event.source,
            'payload': payload_copy,
        }
        # Convert to JSON string and hash
        json_str = json.dumps(canonical, sort_keys=True)
        return hashlib.md5(json_str.encode()).hexdigest()

    async def _handle(self, event: ThreatEvent) -> None:
        # Deduplicate by fingerprint within TTL
        fingerprint = self._get_fingerprint(event)
        now = datetime.now(timezone.utc).timestamp()
        # Clean old entries
        self._recent_fingerprints = deque(
            [(fp, ts) for fp, ts in self._recent_fingerprints if now - ts < self._fingerprint_ttl],
            maxlen=200
        )
        if any(fp == fingerprint for fp, _ in self._recent_fingerprints):
            self.log.debug("Skipping duplicate event (fingerprint) %s", fingerprint)
            return
        self._recent_fingerprints.append((fingerprint, now))

        if not self.can_handle(event):
            return
        self.log.info("Processing event [%s] type=%s sev=%s",
                      event.event_id, event.threat_type.value, event.severity.value)
        try:
            finding = await self.analyse(event)
            if finding:
                await self.bus.publish(finding)
                self.log.info("Finding published — confidence=%.2f actions=%s",
                              finding.confidence, [a.value for a in finding.actions])
        except Exception:
            self.log.exception("Error analysing event %s", event.event_id)

    @abstractmethod
    def can_handle(self, event: ThreatEvent) -> bool: ...

    @abstractmethod
    async def analyse(self, event: ThreatEvent) -> AgentFinding | None: ...