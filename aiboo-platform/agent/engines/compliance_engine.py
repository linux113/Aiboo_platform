from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from core.event_bus import EventBus
from core.events import (
    AgentFinding, Severity, ThreatType, ResponseAction,
)

log = logging.getLogger("ComplianceEngine")

COMPLIANCE_FRAMEWORKS = {
    "GDPR": {
        "name": "General Data Protection Regulation",
        "articles": {
            "art_33": "Data breach notification (72 hours)",
            "art_32": "Security of processing",
            "art_25": "Data protection by design and default",
            "art_5": "Lawfulness, fairness and transparency",
        },
        "mappings": {
            ThreatType.IDENTITY_MISMATCH: ["art_32", "art_5"],
            ThreatType.NETWORK_INTRUSION: ["art_32", "art_33"],
            ThreatType.INSIDER_THREAT: ["art_32", "art_5"],
            ThreatType.DEVICE_HEALTH_FAIL: ["art_32", "art_25"],
            ThreatType.ZERO_TRUST_VIOLATION: ["art_32"],
            ThreatType.ANOMALOUS_BEHAVIOR: ["art_33", "art_32"],
        },
        "breach_notification_threshold": Severity.HIGH,
    },
    "HIPAA": {
        "name": "Health Insurance Portability and Accountability Act",
        "rules": {
            "sec_164_308": "Administrative safeguards",
            "sec_164_310": "Physical safeguards",
            "sec_164_312": "Technical safeguards",
            "sec_164_400": "Breach notification",
        },
        "mappings": {
            ThreatType.IDENTITY_MISMATCH: ["sec_164_312"],
            ThreatType.PHYSICAL_INTRUSION: ["sec_164_310"],
            ThreatType.NETWORK_INTRUSION: ["sec_164_312", "sec_164_308"],
            ThreatType.INSIDER_THREAT: ["sec_164_308", "sec_164_312"],
            ThreatType.DEVICE_HEALTH_FAIL: ["sec_164_312", "sec_164_310"],
        },
        "breach_notification_threshold": Severity.HIGH,
    },
    "PCI_DSS": {
        "name": "Payment Card Industry Data Security Standard",
        "requirements": {
            "req_3": "Protect stored cardholder data",
            "req_4": "Encrypt transmission of cardholder data",
            "req_6": "Develop and maintain secure systems",
            "req_7": "Restrict access to cardholder data",
            "req_10": "Track and monitor all access",
            "req_11": "Regularly test security systems",
            "req_12": "Maintain information security policy",
        },
        "mappings": {
            ThreatType.IDENTITY_MISMATCH: ["req_7", "req_10"],
            ThreatType.NETWORK_INTRUSION: ["req_6", "req_11", "req_4"],
            ThreatType.INSIDER_THREAT: ["req_7", "req_10", "req_12"],
            ThreatType.MEMORY_THREAT: ["req_6", "req_11"],
            ThreatType.ZERO_TRUST_VIOLATION: ["req_7", "req_10"],
        },
        "breach_notification_threshold": Severity.HIGH,
    },
    "SOC_2": {
        "name": "Service Organization Control 2",
        "trust_criteria": {
            "security": "Protected against unauthorized access",
            "availability": "Available for operation and use",
            "processing_integrity": "System processing is complete and accurate",
            "confidentiality": "Information designated as confidential is protected",
            "privacy": "Personal information is collected and used appropriately",
        },
        "mappings": {
            ThreatType.IDENTITY_MISMATCH: ["security", "confidentiality"],
            ThreatType.NETWORK_INTRUSION: ["security", "availability"],
            ThreatType.INSIDER_THREAT: ["confidentiality", "privacy"],
            ThreatType.DEVICE_HEALTH_FAIL: ["availability", "security"],
            ThreatType.PHYSICAL_INTRUSION: ["security", "confidentiality"],
        },
        "breach_notification_threshold": Severity.MEDIUM,
    },
}


class ComplianceViolation:
    def __init__(
        self,
        framework: str,
        control_id: str,
        control_name: str,
        severity: Severity,
        description: str,
        finding_id: str,
        timestamp: datetime | None = None,
    ):
        self.framework = framework
        self.control_id = control_id
        self.control_name = control_name
        self.severity = severity
        self.description = description
        self.finding_id = finding_id
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "severity": self.severity.value,
            "description": self.description,
            "finding_id": self.finding_id,
            "timestamp": self.timestamp.isoformat(),
        }


class ComplianceEngine:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._violations: list[ComplianceViolation] = []
        self._running = False
        self._violation_counts: dict[str, int] = defaultdict(int)

    def start(self) -> None:
        self.bus.subscribe(AgentFinding, self._evaluate_compliance)
        log.info(
            "Compliance engine active — monitoring for GDPR, HIPAA, PCI-DSS, SOC 2 violations"
        )

    def stop(self) -> None:
        self._running = False
        log.info("Compliance engine stopped")

    async def _evaluate_compliance(self, finding: AgentFinding) -> None:
        if finding.confidence < 0.3 or finding.severity.weight < Severity.MEDIUM.weight:
            return

        for framework_name, framework in COMPLIANCE_FRAMEWORKS.items():
            mappings = framework.get("mappings", {})
            if finding.threat_type not in mappings:
                continue

            affected_controls = mappings[finding.threat_type]
            is_breach = finding.severity.weight >= framework["breach_notification_threshold"].weight

            for control_id in affected_controls:
                control_name = self._get_control_name(framework, control_id)
                description = (
                    f"[{framework_name}] {control_name} potentially violated "
                    f"by {finding.agent_name}: {finding.summary[:100]}"
                )

                violation = ComplianceViolation(
                    framework=framework_name,
                    control_id=control_id,
                    control_name=control_name,
                    severity=finding.severity if is_breach else Severity.LOW,
                    description=description,
                    finding_id=finding.event_id,
                )
                self._violations.append(violation)
                key = f"{framework_name}:{control_id}"
                self._violation_counts[key] += 1

                if violation.severity.weight >= Severity.HIGH.weight:
                    log.warning(
                        "COMPLIANCE [%s] %s — %s (severity=%s, breach=%s)",
                        framework_name, control_id, description[:80],
                        violation.severity.value, is_breach,
                    )

                if is_breach and finding.severity == Severity.CRITICAL:
                    log.critical(
                        "BREACH NOTIFICATION REQUIRED — %s control %s violated",
                        framework_name, control_id,
                    )

        if len(self._violations) > 10000:
            self._violations = self._violations[-5000:]

    def _get_control_name(self, framework: dict, control_id: str) -> str:
        for key in ("articles", "rules", "requirements", "trust_criteria"):
            if key in framework and control_id in framework[key]:
                return framework[key][control_id]
        return control_id

    def get_violations(
        self,
        framework: str | None = None,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[dict]:
        result = self._violations
        if framework:
            result = [v for v in result if v.framework == framework]
        if severity:
            result = [v for v in result if v.severity == severity]
        return [v.to_dict() for v in result[-limit:]]

    def get_compliance_summary(self) -> dict:
        summary = {}
        for v in self._violations:
            if v.framework not in summary:
                summary[v.framework] = {
                    "total_violations": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "affected_controls": set(),
                }
            s = summary[v.framework]
            s["total_violations"] += 1
            s[v.severity.value] += 1
            s["affected_controls"].add(v.control_id)

        for fw in summary:
            summary[fw]["affected_controls"] = list(summary[fw]["affected_controls"])

        return summary

    def get_breach_notifications(self, since: datetime | None = None) -> list[dict]:
        result = []
        since_aware = since if since is None or since.tzinfo is not None else since.replace(tzinfo=timezone.utc)
        for v in self._violations:
            if v.severity in (Severity.HIGH, Severity.CRITICAL):
                if since_aware and v.timestamp < since_aware:
                    continue
                result.append(v.to_dict())
        return result
