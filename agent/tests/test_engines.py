import pytest
from datetime import datetime, timezone, timedelta

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, AgentFinding, ThreatType, Severity, ResponseAction,
)


class TestCorrelationEngine:
    @pytest.fixture
    def engine(self, event_bus):
        from engines.correlation_engine import CorrelationEngine
        return CorrelationEngine(event_bus)

    @pytest.mark.asyncio
    async def test_start_subscribes(self, engine, event_bus):
        engine.start()
        assert AgentFinding in event_bus._subscribers

    @pytest.mark.asyncio
    async def test_ingest_stores_finding(self, engine, make_finding):
        engine.start()
        finding = make_finding(threat_type=ThreatType.NETWORK_INTRUSION, user_id="u1")
        await engine._ingest(finding)
        assert len(engine._buffer[ThreatType.NETWORK_INTRUSION]) == 1

    @pytest.mark.asyncio
    async def test_evict_stale(self, engine, make_finding):
        engine.start()
        old = make_finding(
            threat_type=ThreatType.NETWORK_INTRUSION, user_id="u1",
        )
        old.timestamp = datetime.now(timezone.utc) - timedelta(seconds=1000)
        engine._buffer[ThreatType.NETWORK_INTRUSION].append(old)
        engine._evict_stale()
        assert len(engine._buffer[ThreatType.NETWORK_INTRUSION]) == 0

    @pytest.mark.asyncio
    async def test_extract_entity_from_metadata(self, engine, make_finding):
        engine.start()
        finding = make_finding(user_id="user123", src_ip="10.0.0.1")
        entity = engine._extract_entity(finding)
        assert entity == "user123"

    @pytest.mark.asyncio
    async def test_extract_entity_from_payload(self, engine):
        finding = AgentFinding(
            agent_name="Test", event_id="e1",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, confidence=0.5,
            summary="test", actions=[],
            metadata={"payload": {"user_id": "payload_user"}},
        )
        entity = engine._extract_entity(finding)
        assert entity == "payload_user"


class TestComplianceEngine:
    @pytest.fixture
    def engine(self, event_bus):
        from engines.compliance_engine import ComplianceEngine
        return ComplianceEngine(event_bus)

    @pytest.mark.asyncio
    async def test_start_subscribes(self, engine, event_bus):
        engine.start()
        assert AgentFinding in event_bus._subscribers

    @pytest.mark.asyncio
    async def test_gdpr_violation_detected(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="CyberThreatAgent",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.CRITICAL,
            confidence=0.9,
            user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        assert len(engine._violations) > 0
        gdpr_violations = [v for v in engine._violations if v.framework == "GDPR"]
        assert len(gdpr_violations) > 0

    @pytest.mark.asyncio
    async def test_low_confidence_ignored(self, engine, low_confidence_finding):
        engine.start()
        await engine._evaluate_compliance(low_confidence_finding)
        assert len(engine._violations) == 0

    @pytest.mark.asyncio
    async def test_compliance_summary(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH,
            user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        summary = engine.get_compliance_summary()
        assert len(summary) > 0
        for fw_data in summary.values():
            assert fw_data["total_violations"] > 0
            assert "affected_controls" in fw_data

    @pytest.mark.asyncio
    async def test_breach_notifications(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.CRITICAL,
            user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        breaches = engine.get_breach_notifications()
        assert len(breaches) > 0
        for b in breaches:
            assert b["severity"] in ("high", "critical")

    @pytest.mark.asyncio
    async def test_filter_by_framework(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH,
            user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        gdpr_only = engine.get_violations(framework="GDPR")
        for v in gdpr_only:
            assert v["framework"] == "GDPR"

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        high_only = engine.get_violations(severity=Severity.HIGH)
        for v in high_only:
            assert v["severity"] == Severity.HIGH.value

    @pytest.mark.asyncio
    async def test_hipaa_mapping(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent", threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=Severity.HIGH, user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        hipaa = [v for v in engine._violations if v.framework == "HIPAA"]
        assert len(hipaa) > 0

    @pytest.mark.asyncio
    async def test_pci_dss_mapping(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        pci = [v for v in engine._violations if v.framework == "PCI_DSS"]
        assert len(pci) > 0

    @pytest.mark.asyncio
    async def test_soc2_mapping(self, engine, make_finding):
        engine.start()
        finding = make_finding(
            agent_name="TestAgent", threat_type=ThreatType.DEVICE_HEALTH_FAIL,
            severity=Severity.HIGH, user_id="u1",
        )
        await engine._evaluate_compliance(finding)
        soc2 = [v for v in engine._violations if v.framework == "SOC_2"]
        assert len(soc2) > 0

    @pytest.mark.asyncio
    async def test_stop(self, engine):
        engine._running = True
        engine.stop()
        assert engine._running is False


class TestAnomalyDetectionEngine:
    @pytest.fixture
    def engine(self, event_bus):
        from engines.anomaly_detection_engine import AnomalyDetectionEngine
        return AnomalyDetectionEngine(event_bus, zscore_threshold=1.5)

    @pytest.mark.asyncio
    async def test_start_subscribes(self, engine, event_bus):
        engine.start()
        assert AgentFinding in event_bus._subscribers
        assert ThreatEvent in event_bus._subscribers

    @pytest.mark.asyncio
    async def test_get_baseline_creates_new(self, engine):
        bl = engine._get_baseline("test_metric")
        assert bl.name == "test_metric"
        assert bl.name in engine._baselines

    @pytest.mark.asyncio
    async def test_baseline_tracks_values(self, engine):
        bl = engine._get_baseline("test_metric")
        bl.add_value(10.0)
        bl.add_value(20.0)
        bl.add_value(30.0)
        stats = bl.get_statistics()
        assert stats["count"] == 3
        assert stats["mean"] == 20.0
        assert stats["min"] == 10.0
        assert stats["max"] == 30.0

    @pytest.mark.asyncio
    async def test_zscore_calculation(self, engine):
        bl = engine._get_baseline("test_zscore")
        for v in [10, 11, 9, 10.5, 9.5, 10.2, 9.8]:
            bl.add_value(float(v))
        zscore = bl.calculate_zscore(20.0)
        assert zscore > 1.0

    @pytest.mark.asyncio
    async def test_zscore_low_for_normal_value(self, engine):
        bl = engine._get_baseline("test_zscore_normal")
        for v in [10, 11, 9, 10.5, 9.5]:
            bl.add_value(float(v))
        zscore = bl.calculate_zscore(10.0)
        assert zscore < 1.0

    @pytest.mark.asyncio
    async def test_zscore_zero_with_few_samples(self, engine):
        bl = engine._get_baseline("few_samples")
        bl.add_value(10.0)
        assert bl.calculate_zscore(100.0) == 0.0

    @pytest.mark.asyncio
    async def test_finding_ingestion_builds_baseline(self, engine, make_finding):
        engine.start()
        finding = make_finding(confidence=0.8, risk_score=0.9, user_id="u1")
        await engine._ingest_finding(finding)
        assert "finding:network_intrusion" in engine._baselines
        assert "meta:risk_score" in engine._baselines

    @pytest.mark.asyncio
    async def test_entity_rate_tracking(self, engine, make_finding):
        engine.start()
        f1 = make_finding(user_id="u1")
        f2 = make_finding(user_id="u1")
        await engine._ingest_finding(f1)
        await engine._ingest_finding(f2)
        rates = engine.get_entity_rates("u1")
        assert len(rates) > 0

    @pytest.mark.asyncio
    async def test_event_metric_detects_anomaly(self, engine, make_threat_event):
        engine.start()
        bl = engine._get_baseline("event:packet_rate")
        for v in [100, 110, 90, 105, 95]:
            bl.add_value(float(v))

        event = make_threat_event(
            source="sensor", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, packet_rate=500,
        )
        await engine._ingest_event(event)
        anomalies = engine.get_anomalies()
        assert len(anomalies) > 0

    @pytest.mark.asyncio
    async def test_stop(self, engine):
        engine._running = True
        engine.stop()
        assert engine._running is False

    @pytest.mark.asyncio
    async def test_get_baseline_summary(self, engine):
        bl = engine._get_baseline("test_metric")
        bl.add_value(10.0)
        bl.add_value(20.0)
        summary = engine.get_baseline_summary()
        assert "test_metric" in summary
        assert summary["test_metric"]["mean"] == 15.0

    @pytest.mark.asyncio
    async def test_low_confidence_finding_ignored(self, engine, low_confidence_finding):
        engine.start()
        await engine._ingest_finding(low_confidence_finding)
        rates = engine.get_entity_rates()
        assert len(rates) == 0

    @pytest.mark.asyncio
    async def test_anomaly_publishes_finding(self, event_bus):
        from engines.anomaly_detection_engine import AnomalyDetectionEngine
        engine = AnomalyDetectionEngine(event_bus, zscore_threshold=1.5)
        published = []

        async def capture(finding):
            published.append(finding)

        event_bus.subscribe(AgentFinding, capture)
        engine.start()

        bl = engine._get_baseline("event:data_volume_gb")
        for v in [1, 1.1, 0.9, 1.05, 0.95]:
            bl.add_value(float(v))

        event = ThreatEvent(
            source="sensor", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            payload={"data_volume_gb": 50},
        )
        await engine._ingest_event(event)
        assert len(published) > 0
        assert published[0].agent_name == "AnomalyDetectionEngine"


class TestAutonomousResponseEngine:
    @pytest.fixture
    def engine(self, event_bus):
        from engines.autonomous_response import AutonomousResponseEngine
        return AutonomousResponseEngine(event_bus)

    @pytest.mark.asyncio
    async def test_start_subscribes(self, engine, event_bus):
        from core.events import CorrelatedAlert
        engine.start()
        assert CorrelatedAlert in event_bus._subscribers
