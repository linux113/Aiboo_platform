"""
correlation_engine.py — Cyber-Physical & Zero Trust Correlation Engine

Collects AgentFindings and searches for cross-domain patterns
that indicate a coordinated attack (e.g. simultaneous network
intrusion + physical access attempt by the same identity).

Now includes Layer 2 patterns:
- Insider threat + threat intelligence
- Physical-cyber mismatch + insider threat
- Behavioral anomaly + threat intelligence
- High composite risk + network intrusion

Emits a CorrelatedAlert when linked evidence is found.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from core.event_bus import EventBus
from core.events import (
    AgentFinding, CorrelatedAlert,
    ResponseAction, Severity, ThreatType,
)


def _ts_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

log = logging.getLogger("CorrelationEngine")

# How long to keep unmatched findings before expiry (extended for Layer 2)
_WINDOW_SECONDS = 300  # 5 minutes

# Multi-domain threat patterns we look for (including Zero Trust and Layer 2)
_PATTERNS: list[dict] = [
    # ---- Existing patterns ----
    {
        "name":        "Coordinated cyber-physical intrusion",
        "types":       {ThreatType.NETWORK_INTRUSION, ThreatType.PHYSICAL_INTRUSION},
        "min_severity": Severity.HIGH,
        "boost":        0.15,
    },
    {
        "name":        "Identity compromise with lateral movement",
        "types":       {ThreatType.IDENTITY_MISMATCH, ThreatType.NETWORK_INTRUSION},
        "min_severity": Severity.MEDIUM,
        "boost":        0.10,
    },
    {
        "name":        "Insider data theft with surveillance evasion",
        "types":       {ThreatType.INSIDER_THREAT, ThreatType.PHYSICAL_INTRUSION},
        "min_severity": Severity.MEDIUM,
        "boost":        0.10,
    },
    {
        "name":        "Full-spectrum converged attack",
        "types":       {
            ThreatType.NETWORK_INTRUSION,
            ThreatType.IDENTITY_MISMATCH,
            ThreatType.PHYSICAL_INTRUSION,
        },
        "min_severity": Severity.HIGH,
        "boost":        0.20,
    },

    # ---- Zero Trust patterns ----
    {
        "name":        "Impossible travel with identity compromise",
        "types":       {ThreatType.GEO_VELOCITY, ThreatType.IDENTITY_MISMATCH},
        "min_severity": Severity.HIGH,
        "boost":        0.25,
    },
    {
        "name":        "Device health failure followed by network intrusion",
        "types":       {ThreatType.DEVICE_HEALTH_FAIL, ThreatType.NETWORK_INTRUSION},
        "min_severity": Severity.HIGH,
        "boost":        0.20,
    },
    {
        "name":        "Behavioral anomaly with access violation",
        "types":       {ThreatType.BEHAVIORAL_ANOMALY, ThreatType.ZERO_TRUST_VIOLATION},
        "min_severity": Severity.MEDIUM,
        "boost":        0.15,
    },
    {
        "name":        "Zero Trust violation with insider threat",
        "types":       {ThreatType.ZERO_TRUST_VIOLATION, ThreatType.INSIDER_THREAT},
        "min_severity": Severity.HIGH,
        "boost":        0.20,
    },
    {
        "name":        "Multiple Zero Trust violations (geo, device, behavior)",
        "types":       {
            ThreatType.GEO_VELOCITY,
            ThreatType.DEVICE_HEALTH_FAIL,
            ThreatType.BEHAVIORAL_ANOMALY,
        },
        "min_severity": Severity.HIGH,
        "boost":        0.30,
    },
    {
        "name":        "Access request denied followed by anomalous behavior",
        "types":       {ThreatType.ACCESS_REQUEST, ThreatType.BEHAVIORAL_ANOMALY},
        "min_severity": Severity.MEDIUM,
        "boost":        0.10,
    },
    {
        "name":        "Correlated Zero Trust + network intrusion",
        "types":       {ThreatType.ZERO_TRUST_VIOLATION, ThreatType.NETWORK_INTRUSION},
        "min_severity": Severity.CRITICAL,
        "boost":        0.25,
    },

    # ---- Layer 2 patterns (new) ----
    {
        "name":        "Insider threat with threat intelligence alert",
        "types":       {ThreatType.INSIDER_THREAT, ThreatType.THREAT_INTEL_ALERT},
        "min_severity": Severity.HIGH,
        "boost":        0.25,
    },
    {
        "name":        "Physical-cyber mismatch with insider threat",
        "types":       {ThreatType.PHYSICAL_CYBER_MISMATCH, ThreatType.INSIDER_THREAT},
        "min_severity": Severity.HIGH,
        "boost":        0.20,
    },
    {
        "name":        "Behavioral anomaly with threat intelligence",
        "types":       {ThreatType.BEHAVIORAL_ANOMALY, ThreatType.THREAT_INTEL_ALERT},
        "min_severity": Severity.MEDIUM,
        "boost":        0.20,
    },
    {
        "name":        "High composite risk with network intrusion",
        "types":       {ThreatType.CORRELATED_ATTACK, ThreatType.NETWORK_INTRUSION},
        "min_severity": Severity.CRITICAL,
        "boost":        0.30,
    },
    {
        "name":        "High composite risk with insider threat",
        "types":       {ThreatType.CORRELATED_ATTACK, ThreatType.INSIDER_THREAT},
        "min_severity": Severity.HIGH,
        "boost":        0.25,
    },
    {
        "name":        "Physical intrusion followed by behavioral anomaly",
        "types":       {ThreatType.PHYSICAL_INTRUSION, ThreatType.BEHAVIORAL_ANOMALY},
        "min_severity": Severity.MEDIUM,
        "boost":        0.15,
    },
    {
        "name":        "Full-spectrum attack with threat intel",
        "types":       {
            ThreatType.NETWORK_INTRUSION,
            ThreatType.IDENTITY_MISMATCH,
            ThreatType.PHYSICAL_INTRUSION,
            ThreatType.THREAT_INTEL_ALERT,
        },
        "min_severity": Severity.CRITICAL,
        "boost":        0.35,
    },
    {
        "name":        "Insider threat with physical-cyber mismatch and data exfil",
        "types":       {
            ThreatType.INSIDER_THREAT,
            ThreatType.PHYSICAL_CYBER_MISMATCH,
            ThreatType.ANOMALOUS_BEHAVIOR,
        },
        "min_severity": Severity.HIGH,
        "boost":        0.30,
    },
]


class CorrelationEngine:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        # Buffer: threat_type → list of recent findings
        self._buffer: dict[ThreatType, list[AgentFinding]] = defaultdict(list)
        # Cache for entity-based correlation (user_id, ip, etc.)
        self._entity_buffer: dict[str, list[AgentFinding]] = defaultdict(list)
        # Track findings from MetaRiskArbiter specifically
        self._meta_risk_findings: list[AgentFinding] = []

    def start(self) -> None:
        self.bus.subscribe(AgentFinding, self._ingest)
        log.info("Correlation engine active — watching for cross-domain, Zero Trust, and Layer 2 patterns.")

    async def _ingest(self, finding: AgentFinding) -> None:
        self._evict_stale()
        self._buffer[finding.threat_type].append(finding)

        # Special handling for MetaRiskArbiter findings (they are of type CORRELATED_ATTACK)
        if finding.agent_name == "MetaRiskArbiter":
            self._meta_risk_findings.append(finding)
            # Keep bounded
            if len(self._meta_risk_findings) > 50:
                self._meta_risk_findings = self._meta_risk_findings[-50:]

        # Also index by entity (user, ip, device) for richer correlation
        entity = self._extract_entity(finding)
        if entity:
            self._entity_buffer[entity].append(finding)
            # Keep entity buffer bounded
            if len(self._entity_buffer[entity]) > 50:
                self._entity_buffer[entity] = self._entity_buffer[entity][-50:]

        log.debug("Buffered finding type=%s from %s", finding.threat_type.value, finding.agent_name)
        await self._evaluate_patterns()

    def _evict_stale(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_WINDOW_SECONDS)
        for ttype in list(self._buffer):
            self._buffer[ttype] = [
                f for f in self._buffer[ttype] if _ts_aware(f.timestamp) > cutoff
            ]
        # Evict entity buffer as well
        for entity in list(self._entity_buffer):
            self._entity_buffer[entity] = [
                f for f in self._entity_buffer[entity] if _ts_aware(f.timestamp) > cutoff
            ]
            if not self._entity_buffer[entity]:
                del self._entity_buffer[entity]

        # Also evict old MetaRisk findings
        self._meta_risk_findings = [f for f in self._meta_risk_findings if _ts_aware(f.timestamp) > cutoff]

    def _extract_entity(self, finding: AgentFinding) -> str | None:
        """Extract a primary entity (user, IP, device) from a finding."""
        meta = finding.metadata
        # Try common fields
        entity = meta.get("user_id") or meta.get("src_ip") or meta.get("device_id") or meta.get("entity_id")
        if entity:
            return str(entity)
        # Also check payload if available in metadata
        if "payload" in meta:
            payload = meta["payload"]
            if isinstance(payload, dict):
                entity = payload.get("user_id") or payload.get("src_ip") or payload.get("device_id") or payload.get("entity_id")
                if entity:
                    return str(entity)
        return None

    async def _evaluate_patterns(self) -> None:
        active_types = {t for t, findings in self._buffer.items() if findings}

        for pattern in _PATTERNS:
            required_types: set[ThreatType] = pattern["types"]
            if not required_types.issubset(active_types):
                continue

            # Gather the most recent finding per required type
            matched: list[AgentFinding] = []
            for ttype in required_types:
                recent = sorted(
                    self._buffer[ttype], key=lambda f: f.timestamp, reverse=True
                )
                if recent:
                    matched.append(recent[0])

            if not matched:
                continue

            # Only fire if aggregate severity meets the pattern threshold
            max_weight = max(f.severity.weight for f in matched)
            if max_weight < pattern["min_severity"].weight:
                continue

            # Also ensure they are from distinct sources or different agents to avoid self-correlation
            # (but we allow same agent if different types)
            await self._emit_correlated_alert(pattern, matched)
            # Clear buffer to avoid duplicate alerts for the same pattern
            for ttype in required_types:
                self._buffer[ttype] = []

    async def _emit_correlated_alert(
        self,
        pattern: dict,
        findings: list[AgentFinding],
    ) -> None:
        avg_conf = sum(f.confidence for f in findings) / len(findings)
        boosted = min(avg_conf + pattern["boost"], 1.0)
        max_sev = max(findings, key=lambda f: f.severity.weight).severity

        # Union all recommended actions
        all_actions: list[ResponseAction] = []
        for f in findings:
            all_actions.extend(f.actions)
        all_actions = list(dict.fromkeys(all_actions))

        # Escalate correlated alerts to SOC
        if ResponseAction.ESCALATE_SOC not in all_actions:
            all_actions.append(ResponseAction.ESCALATE_SOC)

        # For Layer 2 patterns with high confidence, add stronger actions
        if pattern.get("boost", 0) >= 0.25:
            if ResponseAction.ISOLATE_ASSET not in all_actions:
                all_actions.append(ResponseAction.ISOLATE_ASSET)
            if ResponseAction.NOTIFY_SECURITY not in all_actions:
                all_actions.append(ResponseAction.NOTIFY_SECURITY)

        # If any finding is from MetaRiskArbiter with high score, add PSEUDO_LOCK
        for f in findings:
            if f.agent_name == "MetaRiskArbiter" and f.confidence > 0.7:
                if ResponseAction.PSEUDO_LOCK not in all_actions:
                    all_actions.append(ResponseAction.PSEUDO_LOCK)
                break

        alert = CorrelatedAlert(
            alert_id=str(uuid.uuid4())[:8],
            threat_type=ThreatType.CORRELATED_ATTACK,
            severity=max_sev,
            confidence=round(boosted, 2),
            description=(
                f"[CORRELATED] {pattern['name']}. "
                f"Linked findings: {', '.join(f.agent_name for f in findings)}."
            ),
            findings=findings,
            actions=all_actions,
        )

        log.critical(
            "CORRELATED ALERT [%s] — %s | sev=%s conf=%.2f",
            alert.alert_id, pattern["name"],
            alert.severity.value, alert.confidence,
        )
        await self.bus.publish(alert)