import asyncio
import sys
import os
from datetime import datetime, timezone
from typing import Any

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, AgentFinding, ThreatType, Severity,
    ResponseAction, AccessRequest, ZeroTrustDecision, RiskLevel,
    GateLevel, GateVerdict, GateDecision, CorrelatedAlert,
)


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def threat_event():
    return ThreatEvent(
        source="test",
        threat_type=ThreatType.NETWORK_INTRUSION,
        severity=Severity.HIGH,
        payload={
            "user_id": "test_user",
            "src_ip": "10.0.0.1",
            "dst_port": 443,
            "message": "test event",
        },
    )


@pytest.fixture
def agent_finding():
    return AgentFinding(
        agent_name="TestAgent",
        event_id="evt_001",
        threat_type=ThreatType.NETWORK_INTRUSION,
        severity=Severity.HIGH,
        confidence=0.85,
        summary="Test finding",
        actions=[ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD],
        metadata={"user_id": "test_user", "src_ip": "10.0.0.1"},
    )


@pytest.fixture
def low_confidence_finding():
    return AgentFinding(
        agent_name="TestAgent",
        event_id="evt_002",
        threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
        severity=Severity.LOW,
        confidence=0.15,
        summary="Low confidence test",
        actions=[ResponseAction.LOG],
        metadata={"user_id": "test_user"},
    )


@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def make_threat_event():
    def _make(
        source: str = "test",
        threat_type: ThreatType = ThreatType.NETWORK_INTRUSION,
        severity: Severity = Severity.MEDIUM,
        **payload,
    ) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            threat_type=threat_type,
            severity=severity,
            payload=payload,
        )
    return _make


@pytest.fixture
def make_finding():
    def _make(
        agent_name: str = "TestAgent",
        confidence: float = 0.7,
        severity: Severity = Severity.HIGH,
        threat_type: ThreatType = ThreatType.NETWORK_INTRUSION,
        **metadata,
    ) -> AgentFinding:
        return AgentFinding(
            agent_name=agent_name,
            event_id=f"evt_{datetime.now(timezone.utc).timestamp()}",
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            summary=f"Test from {agent_name}",
            actions=[ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD],
            metadata=metadata,
        )
    return _make
