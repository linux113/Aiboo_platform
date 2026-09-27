"""
engines/alert_suppression_engine.py — Alert Suppression & Human Feedback Engine

Learns from SOC analyst feedback (true positive / false positive / benign)
and suppresses recurring false positives based on alert fingerprints.

Features:
- Suppression rules based on alert fingerprints (event type, source, entity, signature)
- Configurable TTL and suppression count thresholds
- Audit trail for all suppressed alerts
- Manual override support (add/remove rules)

Part of Layer 2: Detection & Intelligence.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Set, Tuple, Any
from collections import defaultdict, deque
from cachetools import TTLCache

from core.event_bus import EventBus
from core.config import config
from core.events import (
    ThreatEvent, AgentFinding, Severity, ResponseAction
)

log = logging.getLogger("AlertSuppressionEngine")

# ============================================
# Configuration Constants
# ============================================

# Default suppression TTL (seconds)
DEFAULT_SUPPRESSION_TTL = 86400 * 7  # 7 days

# Number of false positive reports needed to automatically suppress
AUTO_SUPPRESSION_THRESHOLD = 2

# Maximum number of suppression rules per fingerprint
MAX_RULES_PER_FINGERPRINT = 10

# Audit history retention (number of entries)
MAX_AUDIT_HISTORY = 10000

# Feedback cooldown to avoid duplicate processing
FEEDBACK_COOLDOWN_SECONDS = 60


@dataclass
class SuppressionRule:
    """Rule for suppressing alerts based on fingerprint."""
    fingerprint: str
    reason: str
    created_by: str  # "system" or "analyst"
    created_at: datetime
    expires_at: Optional[datetime]
    suppression_count: int = 0
    max_suppressions: Optional[int] = None  # None = unlimited
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_active(self) -> bool:
        """Check if rule is still active (not expired)."""
        if self.expires_at is None:
            return True
        return datetime.now(timezone.utc) < self.expires_at

    def should_suppress(self) -> bool:
        """Check if suppression should be applied (count limit check)."""
        if not self.is_active():
            return False
        if self.max_suppressions is not None and self.suppression_count >= self.max_suppressions:
            return False
        return True

    def increment(self) -> None:
        """Increment suppression count."""
        self.suppression_count += 1


@dataclass
class AuditEntry:
    """Audit trail entry for a suppressed alert."""
    alert_id: str
    fingerprint: str
    suppression_rule: SuppressionRule
    original_event: Dict[str, Any]
    timestamp: datetime
    suppressed: bool  # True if suppressed, False if allowed
    reason: str


class AlertSuppressionEngine:
    """
    Alert Suppression Engine.
    Learns from analyst feedback and suppresses false positives.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._suppression_rules: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400 * 7)
        self._audit_trail: deque = deque(maxlen=MAX_AUDIT_HISTORY)
        self._feedback_history: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=86400 * 7)
        self._running = False

        # Cooldown for feedback processing
        self._last_feedback_time: TTLCache = TTLCache(maxsize=config.max_dict_size, ttl=3600)

        # Configuration
        self._config = {
            "default_ttl_seconds": DEFAULT_SUPPRESSION_TTL,
            "auto_suppression_threshold": AUTO_SUPPRESSION_THRESHOLD,
            "feedback_cooldown_seconds": FEEDBACK_COOLDOWN_SECONDS,
        }

        # Load some default suppression rules (optional)
        self._load_default_rules()

        log.info("AlertSuppressionEngine initialized")

    def start(self) -> None:
        """Start the engine: subscribe to relevant events."""
        # Subscribe to AgentFinding (to potentially learn from dispositions)
        # But we primarily rely on explicit feedback calls.
        self.bus.subscribe(AgentFinding, self._on_agent_finding)
        self._running = True
        log.info("AlertSuppressionEngine started")

    # ============================================
    # Feedback Interface (called by SOC analyst / API)
    # ============================================

    def record_feedback(self, fingerprint: str, verdict: str, analyst: str = "system",
                        reason: str = "", metadata: Optional[Dict] = None) -> bool:
        """
        Record analyst feedback for an alert fingerprint.
        Verdict: "true_positive", "false_positive", "benign"
        Returns True if feedback was recorded.
        """
        # Cooldown check
        now = datetime.now(timezone.utc)
        last = self._last_feedback_time.get(fingerprint)
        if last and (now - last).total_seconds() < self._config["feedback_cooldown_seconds"]:
            log.debug(f"Feedback cooldown for {fingerprint}, skipping")
            return False

        self._last_feedback_time[fingerprint] = now

        # Store feedback (TTLCache, no defaultdict)
        feedback_entry = {
            "fingerprint": fingerprint,
            "verdict": verdict,
            "analyst": analyst,
            "timestamp": now,
            "reason": reason,
            "metadata": metadata or {},
        }
        if fingerprint not in self._feedback_history:
            self._feedback_history[fingerprint] = []
        self._feedback_history[fingerprint].append(feedback_entry)

        # If false_positive, trigger auto-suppression if threshold reached
        if verdict == "false_positive":
            self._handle_false_positive(fingerprint, reason, analyst)

        log.info(f"Feedback recorded: {fingerprint} -> {verdict} by {analyst}")
        return True

    def _handle_false_positive(self, fingerprint: str, reason: str, analyst: str) -> None:
        """
        Process a false positive report. If enough reports, create or update suppression rule.
        """
        # Count false positives for this fingerprint
        fh = self._feedback_history.get(fingerprint, [])
        fp_count = sum(1 for fb in fh if fb["verdict"] == "false_positive")

        # If threshold reached, create/update suppression rule
        threshold = self._config["auto_suppression_threshold"]
        if fp_count >= threshold:
            # Check if rule already exists
            if fingerprint in self._suppression_rules:
                rule = self._suppression_rules[fingerprint]
                # Update TTL (reset expiration)
                rule.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._config["default_ttl_seconds"])
                rule.created_by = analyst
                rule.reason = reason or rule.reason
                log.info(f"Updated suppression rule for {fingerprint} (expires at {rule.expires_at})")
            else:
                # Create new rule
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._config["default_ttl_seconds"])
                rule = SuppressionRule(
                    fingerprint=fingerprint,
                    reason=reason or "Auto-suppressed due to repeated false positives",
                    created_by=analyst,
                    created_at=datetime.now(timezone.utc),
                    expires_at=expires_at,
                    max_suppressions=None,  # unlimited
                )
                self._suppression_rules[fingerprint] = rule
                log.info(f"Created suppression rule for {fingerprint} (expires at {expires_at})")

    # ============================================
    # Alert Suppression Check
    # ============================================

    def should_suppress(self, alert: AgentFinding) -> Tuple[bool, Optional[SuppressionRule]]:
        """
        Check if an alert should be suppressed based on its fingerprint.
        Returns (suppressed, rule).
        """
        fingerprint = self._generate_fingerprint(alert)
        rule = self._suppression_rules.get(fingerprint)
        if rule and rule.should_suppress():
            rule.increment()
            return True, rule
        return False, None

    def _generate_fingerprint(self, alert: AgentFinding) -> str:
        """
        Generate a unique fingerprint for an alert.
        Combines: agent_name, threat_type, severity, and key metadata.
        """
        # Extract key fields from metadata
        meta = alert.metadata
        entity = meta.get("user_id") or meta.get("src_ip") or meta.get("device_id") or "unknown"
        signature = meta.get("signature") or meta.get("threat_type") or ""

        # Build fingerprint components
        components = [
            alert.agent_name,
            alert.threat_type.value,
            alert.severity.value,
            str(entity),
            str(signature),
        ]

        # Include custom fields if present
        for key in ["zone", "resource", "dst_port", "process_name"]:
            if meta.get(key):
                components.append(str(meta[key]))

        # Hash to a short string
        raw = "|".join(components)
        fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return fingerprint

    # ============================================
    # Event Handling
    # ============================================

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """
        Intercept agent findings to check for suppression.
        If suppressed, modify the finding to indicate suppression and log it.
        """
        # We don't actually suppress the event itself; we log it and add metadata.
        # The orchestrator or other components can use the suppression status.
        # For now, we'll just log.
        suppressed, rule = self.should_suppress(finding)
        if suppressed:
            # Log suppression to audit trail
            audit = AuditEntry(
                alert_id=finding.event_id,
                fingerprint=self._generate_fingerprint(finding),
                suppression_rule=rule,
                original_event=finding.metadata,
                timestamp=datetime.now(timezone.utc),
                suppressed=True,
                reason=f"Suppressed by rule: {rule.reason} (count={rule.suppression_count})"
            )
            self._audit_trail.append(audit)
            log.info(f"Alert suppressed: {finding.agent_name} {finding.event_id} (fingerprint={audit.fingerprint})")
            # Optionally, we could modify the finding to flag suppression
            # But we leave it as is; the downstream components should check suppression.
        else:
            # Still audit but not suppressed
            audit = AuditEntry(
                alert_id=finding.event_id,
                fingerprint=self._generate_fingerprint(finding),
                suppression_rule=None,
                original_event=finding.metadata,
                timestamp=datetime.now(timezone.utc),
                suppressed=False,
                reason="Not suppressed"
            )
            self._audit_trail.append(audit)

    # ============================================
    # Manual Rule Management
    # ============================================

    def add_suppression_rule(self, fingerprint: str, reason: str, created_by: str = "analyst",
                             ttl_seconds: Optional[int] = None, max_suppressions: Optional[int] = None) -> bool:
        """
        Manually add a suppression rule.
        If fingerprint already exists, update it.
        """
        if fingerprint in self._suppression_rules:
            rule = self._suppression_rules[fingerprint]
            rule.reason = reason
            rule.created_by = created_by
            if ttl_seconds is not None:
                rule.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            if max_suppressions is not None:
                rule.max_suppressions = max_suppressions
            log.info(f"Updated suppression rule for {fingerprint}")
            return True

        expires_at = None
        if ttl_seconds is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        rule = SuppressionRule(
            fingerprint=fingerprint,
            reason=reason,
            created_by=created_by,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            max_suppressions=max_suppressions,
        )
        self._suppression_rules[fingerprint] = rule
        log.info(f"Added suppression rule for {fingerprint}")
        return True

    def remove_suppression_rule(self, fingerprint: str) -> bool:
        """Remove a suppression rule."""
        if fingerprint in self._suppression_rules:
            del self._suppression_rules[fingerprint]
            log.info(f"Removed suppression rule for {fingerprint}")
            return True
        return False

    def get_suppression_rule(self, fingerprint: str) -> Optional[SuppressionRule]:
        """Get a suppression rule."""
        return self._suppression_rules.get(fingerprint)

    def get_all_suppression_rules(self) -> List[SuppressionRule]:
        """Get all active suppression rules."""
        return [r for r in self._suppression_rules.values() if r.is_active()]

    # ============================================
    # Audit Trail
    # ============================================

    def get_audit_trail(self, limit: int = 100, suppressed_only: bool = False) -> List[AuditEntry]:
        """Get audit trail entries."""
        entries = list(self._audit_trail)
        if suppressed_only:
            entries = [e for e in entries if e.suppressed]
        return entries[-limit:]

    def get_feedback_history(self, fingerprint: str) -> List[Dict]:
        """Get feedback history for a fingerprint."""
        return list(self._feedback_history.get(fingerprint, []))

    # ============================================
    # Default Rules (optional)
    # ============================================

    def _load_default_rules(self):
        """Load some default suppression rules (e.g., for common benign alerts)."""
        # Example: suppress low-severity port scans from internal scanning tools
        # This is just a placeholder; real rules would be learned or configured.
        pass

    # ============================================
    # Shutdown
    # ============================================

    def stop(self) -> None:
        """Stop the engine."""
        self._running = False
        log.info("AlertSuppressionEngine stopped")