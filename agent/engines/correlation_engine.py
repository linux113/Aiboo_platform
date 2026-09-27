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

    # Values that identify nobody in particular — never link findings on them
    _IGNORED_ENTITIES = {
        "", "unknown", "none", "null", "-", "?", "n/a",
        "system", "local service", "network service", "anonymous logon",
        "127.0.0.1", "::1", "0.0.0.0", "localhost",
    }
    _ENTITY_KEYS = ("user_id", "src_ip", "entity_id", "target_user", "dst_ip")

    def _entities(self, finding: AgentFinding) -> set[str]:
        """
        Every concrete identity (user / IP) mentioned by a finding.

        Two findings are only linked when they share one of these. Machine
        names are deliberately NOT used: on a single PC every event shares
        the machine name, which linked unrelated events together.
        """
        meta = finding.metadata or {}
        containers = [meta]
        for key in ("payload", "raw_payload"):
            c = meta.get(key)
            if isinstance(c, dict):
                containers.append(c)
                raw = c.get("raw_payload")
                if isinstance(raw, dict):
                    containers.append(raw)

        machine_names = set()
        for c in containers:
            for key in ("device_id", "computer_name"):
                if c.get(key):
                    machine_names.add(str(c[key]).strip().lower())

        found: set[str] = set()
        for c in containers:
            for key in self._ENTITY_KEYS:
                val = c.get(key)
                if val is None or isinstance(val, (dict, list)):
                    continue
                v = str(val).strip().lower()
                if "\\" in v:
                    v = v.split("\\")[-1]
                if v in self._IGNORED_ENTITIES or v.endswith("$") or v in machine_names:
                    continue
                if v.startswith(("dwm-", "umfd-")):
                    continue
                found.add(v)
        return found

    def _match_by_entity(self, required_types: set) -> tuple[list[AgentFinding], str] | tuple[None, None]:
        """
        Find one finding per required type that all mention the same entity.
        Prefers the most recent evidence. Returns (findings, entity).
        """
        # entity -> {threat_type: newest finding}
        by_entity: dict[str, dict] = defaultdict(dict)
        newest_ts: dict[str, datetime] = {}
        for ttype in required_types:
            for f in sorted(self._buffer[ttype], key=lambda x: _ts_aware(x.timestamp), reverse=True):
                for ent in self._entities(f):
                    if ttype not in by_entity[ent]:
                        by_entity[ent][ttype] = f
                        ts = _ts_aware(f.timestamp)
                        if ent not in newest_ts or ts > newest_ts[ent]:
                            newest_ts[ent] = ts

        candidates = [
            ent for ent, per_type in by_entity.items()
            if set(per_type) >= set(required_types)
            # must be at least two different underlying events
            and len({f.event_id for f in per_type.values()}) > 1
        ]
        if not candidates:
            return None, None
        best = max(candidates, key=lambda e: newest_ts.get(e, datetime.min.replace(tzinfo=timezone.utc)))
        return [by_entity[best][t] for t in required_types], best

    async def _evaluate_patterns(self) -> None:
        active_types = {t for t, findings in self._buffer.items() if findings}

        for pattern in _PATTERNS:
            required_types: set[ThreatType] = pattern["types"]
            if not required_types.issubset(active_types):
                continue

            # Only link findings that are about the SAME user or IP.
            # (Before, any two findings within 5 minutes were linked — e.g. a
            # ransomware test got "correlated" with a SYSTEM logon.)
            matched, entity = self._match_by_entity(required_types)
            if not matched:
                continue

            # Only fire if aggregate severity meets the pattern threshold
            max_weight = max(f.severity.weight for f in matched)
            if max_weight < pattern["min_severity"].weight:
                continue

            await self._emit_correlated_alert(pattern, matched, entity)
            # Remove just the linked findings so they aren't reused
            used = {id(f) for f in matched}
            for ttype in required_types:
                self._buffer[ttype] = [f for f in self._buffer[ttype] if id(f) not in used]
            active_types = {t for t, findings in self._buffer.items() if findings}

    async def _emit_correlated_alert(
        self,
        pattern: dict,
        findings: list[AgentFinding],
        entity: str | None = None,
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
                f"[CORRELATED] {pattern['name']}"
                + (f" (same entity: {entity})" if entity else "")
                + f". Linked findings: {', '.join(f.agent_name for f in findings)}."
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