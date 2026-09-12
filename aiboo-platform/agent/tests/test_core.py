import pytest
from datetime import datetime, timezone

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, AgentFinding, ThreatType, Severity,
    ResponseAction, AccessRequest, ZeroTrustDecision, RiskLevel,
)


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, event_bus):
        received = []

        async def handler(event):
            received.append(event)

        event_bus.subscribe(ThreatEvent, handler)
        event = ThreatEvent(
            source="test", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, payload={},
        )
        await event_bus.publish(event)
        assert len(received) == 1
        assert received[0].event_id == event.event_id

    @pytest.mark.asyncio
    async def test_no_subscribers(self, event_bus, caplog):
        event = ThreatEvent(
            source="test", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, payload={},
        )
        await event_bus.publish(event)
        assert any("No subscribers" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, event_bus):
        results = []

        async def handler1(event):
            results.append("h1")

        async def handler2(event):
            results.append("h2")

        event_bus.subscribe(ThreatEvent, handler1)
        event_bus.subscribe(ThreatEvent, handler2)
        event = ThreatEvent(
            source="test", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, payload={},
        )
        await event_bus.publish(event)
        assert len(results) == 2
        assert "h1" in results
        assert "h2" in results

    @pytest.mark.asyncio
    async def test_different_event_types(self, event_bus):
        threat_results = []
        finding_results = []

        async def threat_handler(e):
            threat_results.append(e)

        async def finding_handler(e):
            finding_results.append(e)

        event_bus.subscribe(ThreatEvent, threat_handler)
        event_bus.subscribe(AgentFinding, finding_handler)

        te = ThreatEvent(source="t", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.LOW, payload={})
        af = AgentFinding(agent_name="a", event_id="e1",
                          threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                          severity=Severity.LOW, confidence=0.5,
                          summary="test", actions=[])

        await event_bus.publish(te)
        await event_bus.publish(af)

        assert len(threat_results) == 1
        assert len(finding_results) == 1

    @pytest.mark.asyncio
    async def test_subscriber_error_handling(self, event_bus):
        async def failing_handler(event):
            raise ValueError("handler error")

        async def good_handler(event):
            pass

        event_bus.subscribe(ThreatEvent, failing_handler)
        event_bus.subscribe(ThreatEvent, good_handler)

        event = ThreatEvent(
            source="test", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, payload={},
        )
        await event_bus.publish(event)


class TestThreatEvent:
    def test_create_threat_event(self):
        event = ThreatEvent(
            source="test_source",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.CRITICAL,
            payload={"key": "value"},
        )
        assert event.source == "test_source"
        assert event.threat_type == ThreatType.NETWORK_INTRUSION
        assert event.severity == Severity.CRITICAL
        assert event.payload == {"key": "value"}
        assert event.event_id is not None
        assert len(event.event_id) == 8
        assert event.timestamp is not None

    def test_default_event_id_generated(self):
        e1 = ThreatEvent(source="s", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.LOW, payload={})
        e2 = ThreatEvent(source="s", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.LOW, payload={})
        assert e1.event_id != e2.event_id

    def test_severity_weight(self):
        assert Severity.LOW.weight == 1
        assert Severity.MEDIUM.weight == 2
        assert Severity.HIGH.weight == 3
        assert Severity.CRITICAL.weight == 4


class TestAgentFinding:
    def test_create_finding(self):
        finding = AgentFinding(
            agent_name="TestAgent",
            event_id="evt_001",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH,
            confidence=0.85,
            summary="Test finding",
            actions=[ResponseAction.LOG, ResponseAction.ISOLATE_ASSET],
            metadata={"src_ip": "10.0.0.1"},
        )
        assert finding.agent_name == "TestAgent"
        assert finding.confidence == 0.85
        assert len(finding.actions) == 2
        assert finding.metadata["src_ip"] == "10.0.0.1"

    def test_finding_without_metadata(self):
        finding = AgentFinding(
            agent_name="Agent", event_id="e1",
            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
            severity=Severity.LOW, confidence=0.3,
            summary="test", actions=[],
        )
        assert finding.metadata == {}


class TestAccessRequest:
    def test_create_access_request(self):
        ts = datetime.now(timezone.utc)
        req = AccessRequest(
            user_id="user1",
            device_id="device1",
            resource="server_room",
            timestamp=ts,
            location="office",
            network="corporate",
            behavior_context={"login_hour": 9},
        )
        assert req.user_id == "user1"
        assert req.resource == "server_room"
        assert req.location == "office"
        assert req.behavior_context["login_hour"] == 9


class TestZeroTrustDecision:
    def test_create_decision(self):
        decision = ZeroTrustDecision(
            request_id="req_001",
            allowed=True,
            risk_level=RiskLevel.LOW,
            required_actions=[ResponseAction.LOG],
            reason="All conditions met",
            confidence=0.95,
        )
        assert decision.allowed is True
        assert decision.risk_level == RiskLevel.LOW
        assert decision.confidence == 0.95
