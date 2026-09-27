"""
event_bus.py — Async publish/subscribe event bus.
 
All agents subscribe to ThreatEvents and publish AgentFindings back.
The orchestrator listens to AgentFindings and routes them to the
correlation engine and command dashboard.
"""
 
from __future__ import annotations
 
import asyncio
import logging
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine
 
log = logging.getLogger("EventBus")
 
Handler = Callable[[Any], Coroutine[Any, Any, None]]
 
 
class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[type, list[Handler]] = defaultdict(list)
        # Deduplication cache for ThreatEvents
        self._recent_event_fingerprints = deque(maxlen=1000)
        self._fingerprint_ttl = 60  # seconds

    def _get_fingerprint(self, event: Any) -> str | None:
        """Generate fingerprint for ThreatEvent based on logical content."""
        if not hasattr(event, 'payload') or not hasattr(event, 'threat_type') or not hasattr(event, 'source'):
            return None
        # Exclude timestamp and event_id from payload
        p = event.payload.copy() if hasattr(event.payload, 'copy') else dict(event.payload)
        for key in ('timestamp', 'event_id', 'time_generated'):
            p.pop(key, None)
        canonical = {
            'threat_type': event.threat_type.value,
            'source': event.source,
            'payload': p,
        }
        json_str = json.dumps(canonical, sort_keys=True)
        return hashlib.md5(json_str.encode()).hexdigest()

    def _is_duplicate(self, event: Any) -> bool:
        """Check if a ThreatEvent is a duplicate within TTL."""
        fp = self._get_fingerprint(event)
        if fp is None:
            return False
        now = datetime.now(timezone.utc).timestamp()
        # Clean old entries
        self._recent_event_fingerprints = deque(
            [(f, t) for f, t in self._recent_event_fingerprints if now - t < self._fingerprint_ttl],
            maxlen=1000
        )
        if any(f == fp for f, _ in self._recent_event_fingerprints):
            return True
        self._recent_event_fingerprints.append((fp, now))
        return False

    def subscribe(self, event_type: type, handler: Handler) -> None:
        self._subscribers[event_type].append(handler)
        log.debug("Subscribed %s to %s", handler.__qualname__, event_type.__name__)
 
    async def publish(self, event: Any) -> None:
        event_type = type(event)
        # Deduplicate ThreatEvents
        if event_type.__name__ == 'ThreatEvent' and self._is_duplicate(event):
            log.debug("Dropping duplicate ThreatEvent %s", getattr(event, 'event_id', 'unknown'))
            return
        handlers = self._subscribers.get(event_type, [])
        if not handlers:
            log.warning("No subscribers for event type %s", event_type.__name__)
            return
        log.debug("Publishing %s to %d subscribers", event_type.__name__, len(handlers))
        await asyncio.gather(*(h(event) for h in handlers))