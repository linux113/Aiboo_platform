"""
TriGate v2 tests - Gate 1 Trust, Gate 2 Intent, Gate 3 Impact, the combined
decision, learning / memory on disk, and the three old bugs:

  * Gate 2 used `reason` before it was assigned (crash)
  * off-hours was checked in UTC instead of local time
  * Gate 1's 5-second de-duplication hid brute force
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from core.event_bus import EventBus
from core.events import GateDecision, GateLevel, GateVerdict, ResponseAction, Severity, ThreatEvent, ThreatType
from gates import Gate1Trust, Gate2Intent, Gate3Impact
from gates.gate1_perimeter import build_context, score_trust
from gates.gate2_behavioural import score_intent
from gates.gate3_adaptive import recommend, risk_level, score_impact
from gates.threat_intel_lookup import ThreatIntelLookup, configure_threat_intel
from gates.trigate_memory import TriGateMemory, set_memory, get_memory
from gates.trigate_patterns import (
    classify, configure_settings, ip_kind, local_time, logon_kind, parse_business_hours,
)

AFTERNOON = datetime.now().replace(hour=14, minute=10, second=0, microsecond=0)   # local, naive
NIGHT = datetime.now().replace(hour=2, minute=30, second=0, microsecond=0)


@pytest.fixture(autouse=True)
def fresh_trigate(tmp_path):
    """Each test: empty RAM memory, default settings, empty blocklist."""
    set_memory(TriGateMemory(None))
    configure_settings("8-20", "normal")
    configure_threat_intel(blocklist_path=str(tmp_path / "blocklist.txt"), abuseipdb_key="")
    yield
    set_memory(TriGateMemory(None))
    configure_threat_intel()


_rec = [0]


def win_event(eid, threat=ThreatType.IDENTITY_MISMATCH, sev=Severity.HIGH, ts=AFTERNOON, **payload):
    _rec[0] += 1
    payload.setdefault("record_number", _rec[0])
    payload.update(event_id_raw=eid, computer_name="GORILLA", log_name="Security")
    return ThreatEvent(source="windows_event_log:Security", threat_type=threat, severity=sev,
                       payload=payload, timestamp=ts)


def brute(n=5, user="aibootest", **extra):
    p = dict(user_id=user, failure_reason="wrong password", logon_type="interactive (keyboard)",
             src_ip="unknown", workstation="GORILLA", brute_force=True, failed_attempts=n)
    p.update(extra)
    return win_event(4625, **p)


@pytest.fixture
def pipeline():
    bus = EventBus()
    finals, all_decisions = [], []
    for g in (Gate1Trust(bus), Gate2Intent(bus), Gate3Impact(bus)):
        g.start()

    async def cap(d):
        all_decisions.append(d)
        if d.gate == GateLevel.GATE_3:
            finals.append(d)
    bus.subscribe(GateDecision, cap)
    return bus, finals, all_decisions


def tri(d):
    return d.metadata["trigate"]


def texts(gate):
    return " | ".join(f["text"] for f in gate["factors"])


# ---------------------------------------------------------------- patterns
class TestPatterns:
    def test_classify_windows_events(self):
        assert classify(brute()).key == "brute_force"
        assert classify(win_event(4625, user_id="x")).key == "failed_logon"
        assert classify(win_event(1102)).key == "log_cleared"
        assert classify(win_event(4732, privileged_group=True)).key == "admin_group_add"
        assert classify(win_event(4732, privileged_group=False)).key == "group_add"
        assert classify(win_event(7045)).key == "service_installed"
        assert classify(win_event(4698)).key == "scheduled_task"
        assert classify(win_event(4720)).key == "account_created"
        assert classify(win_event(4740)).key == "account_lockout"

    def test_ip_and_logon_kinds(self):
        assert ip_kind("8.8.8.8") == "public"
        assert ip_kind("192.168.1.5") == "private"
        assert ip_kind("127.0.0.1") == "local"
        assert ip_kind("unknown") == "none"
        assert logon_kind("remote desktop (RDP)") == "remote"
        assert logon_kind("network (clear-text)") == "clear_text"
        assert logon_kind("interactive (keyboard)") == "local"
        assert logon_kind("new credentials (RunAs)") == "runas"

    def test_business_hours_parsing(self):
        assert parse_business_hours("9-18") == (9, 18)
        assert parse_business_hours("garbage") == (8, 20)
        assert parse_business_hours("20-8") == (8, 20)


# ---------------------------------------------------------------- Gate 1
class TestGate1Trust:
    def test_brute_force_gives_low_trust(self):
        score, f = score_trust(build_context(brute()))
        assert score < 40
        assert "failed logons" in " ".join(x["text"] for x in f)

    def test_remote_internet_logon_less_trusted_than_local(self):
        local, _ = score_trust(build_context(win_event(4625, user_id="bob", failure_reason="wrong password",
                                                       logon_type="interactive (keyboard)")))
        remote, f = score_trust(build_context(win_event(4625, user_id="bob", failure_reason="wrong password",
                                                        logon_type="remote desktop (RDP)", src_ip="185.1.2.3")))
        assert remote < local - 30
        joined = " ".join(x["text"] for x in f)
        assert "Remote logon" in joined and "internet address" in joined

    def test_known_user_and_ip_raise_trust(self):
        ev = lambda: win_event(4625, user_id="alice", failure_reason="wrong password",
                               logon_type="network", src_ip="192.168.1.20")
        before, _ = score_trust(build_context(ev()))
        get_memory().record_logon("alice", "192.168.1.20", "network")
        after, f = score_trust(build_context(ev()))
        assert after >= before + 20
        assert "logged in from 192.168.1.20 before" in " ".join(x["text"] for x in f)

    def test_nonexistent_user_name_lowers_trust(self):
        a, _ = score_trust(build_context(win_event(4625, user_id="x", failure_reason="wrong password")))
        b, _ = score_trust(build_context(win_event(4625, user_id="x", failure_reason="user name does not exist")))
        assert b < a

    def test_admin_change_entity_is_actor_subject_is_target(self):
        ctx = build_context(win_event(4732, user_id="lalit", actor="lalit", target_user="eve",
                                      group="Administrators", privileged_group=True))
        assert ctx["entity"] == "lalit" and ctx["subject"] == "eve"


# ---------------------------------------------------------------- Gate 2
class TestGate2Intent:
    @pytest.mark.asyncio
    async def test_pattern_base_with_mitre(self):
        score, f = await score_intent(build_context(win_event(1102, user_id="lalit", actor="lalit")))
        assert score >= 90
        assert "T1070.001" in f[0]["text"]

    @pytest.mark.asyncio
    async def test_off_hours_uses_local_time(self):
        night, f = await score_intent(build_context(brute(ts=NIGHT)))
        day, f2 = await score_intent(build_context(brute(ts=AFTERNOON)))
        assert night == day + 10
        assert any("outside working hours" in x["text"] for x in f)
        assert not any("outside working hours" in x["text"] for x in f2)

    @pytest.mark.asyncio
    async def test_utc_timestamp_is_converted_to_local(self, monkeypatch):
        """Bug fix: 05:00 UTC is 10:30 in India - working hours, not off-hours."""
        if not hasattr(time, "tzset"):
            pytest.skip("tzset not available on this OS")
        monkeypatch.setenv("TZ", "Asia/Kolkata")
        time.tzset()
        try:
            utc_morning = datetime.now(timezone.utc).replace(hour=5, minute=0, second=0, microsecond=0)
            assert local_time(utc_morning).hour == 10
            _, f = await score_intent(build_context(brute(ts=utc_morning)))
            assert not any("outside working hours" in x["text"] for x in f)
            utc_evening = utc_morning.replace(hour=21)            # 02:30 IST
            _, f = await score_intent(build_context(brute(ts=utc_evening)))
            assert any("02:30" in x["text"] for x in f)
        finally:
            monkeypatch.delenv("TZ", raising=False)
            time.tzset()

    @pytest.mark.asyncio
    async def test_history_raises_intent(self):
        first, _ = await score_intent(build_context(brute()))
        get_memory().record_event("old1", "aibootest", "failed_logon", 40)
        get_memory().record_event("old2", "aibootest", "brute_force", 60)
        second, f = await score_intent(build_context(brute()))
        assert second == first + 10
        assert any("last 24 hours" in x["text"] for x in f)

    @pytest.mark.asyncio
    async def test_blocklist_threat_intel(self, tmp_path):
        bl = tmp_path / "blocklist.txt"
        bl.write_text("# bad\n185.220.101.0/24\n")
        configure_threat_intel(blocklist_path=str(bl))
        ctx = build_context(win_event(4625, user_id="bob", failure_reason="wrong password",
                                      logon_type="remote desktop (RDP)", src_ip="185.220.101.7"))
        score, f = await score_intent(ctx)
        assert any("blocklist" in x["text"] and x["points"] == 30 for x in f)

    @pytest.mark.asyncio
    async def test_abuseipdb_never_queried_for_private_ip(self):
        intel = ThreatIntelLookup(blocklist_path=None, abuseipdb_key="dummy")
        assert await intel._check_abuseipdb("192.168.1.10") is None

    @pytest.mark.asyncio
    async def test_suspicious_service_command(self):
        sus, f = await score_intent(build_context(win_event(
            7045, service_name="upd", image_path="powershell -enc AAAA")))
        normal, _ = await score_intent(build_context(win_event(
            7045, service_name="svc", image_path="C:\\Program Files\\Vendor\\svc.exe")))
        assert sus > normal + 20


# ---------------------------------------------------------------- Gate 3
class TestGate3Impact:
    def test_importance_changes_impact(self):
        ctx = build_context(win_event(1102, user_id="lalit", actor="lalit"))
        normal, f, imp = score_impact(ctx)
        assert imp == "normal"
        get_memory().set_importance("critical")
        critical, f2, imp2 = score_impact(ctx)
        assert imp2 == "critical" and critical == normal + 45
        assert "CRITICAL" in f2[0]["text"]

    def test_config_default_importance(self):
        configure_settings("8-20", "server")      # alias -> high
        _, f, imp = score_impact(build_context(brute()))
        assert imp == "high" and "config.ini" in f[0]["text"]

    def test_admin_and_evidence_factors(self):
        _, f, _ = score_impact(build_context(win_event(4732, actor="a", target_user="b", privileged_group=True)))
        assert any("administrator rights" in x["text"] for x in f)
        _, f, _ = score_impact(build_context(win_event(1102, actor="a")))
        assert any("evidence" in x["text"] for x in f)

    def test_recommendations_target_the_new_admin_not_the_actor(self):
        ctx = build_context(win_event(4732, user_id="lalit", actor="lalit", target_user="eve",
                                      privileged_group=True))
        recs = recommend(ctx, "high")
        assert {"action": "revoke_identity", "target": "eve"}.items() <= recs[0].items()
        assert all(r["target"] != "lalit" for r in recs if r["action"] == "revoke_identity")

    def test_low_risk_recommends_nothing(self):
        assert recommend(build_context(brute()), "low")[0]["action"] == "log"

    def test_risk_levels(self):
        assert risk_level(80) == "critical" and risk_level(60) == "high"
        assert risk_level(40) == "medium" and risk_level(10) == "low"


# ------------------------------------------------------ full pipeline
class TestPipeline:
    @pytest.mark.asyncio
    async def test_every_event_goes_through_all_three_gates(self, pipeline):
        bus, finals, decisions = pipeline
        await bus.publish(win_event(4720, user_id="lalit", actor="lalit", target_user="x"))
        gates = [d.gate for d in decisions]
        assert gates == [GateLevel.GATE_1, GateLevel.GATE_2, GateLevel.GATE_3]
        t = tri(finals[0])
        for key in ("trust", "intent", "impact", "risk", "recommended"):
            assert key in t
        assert 0 <= t["risk"]["score"] <= 100

    @pytest.mark.asyncio
    async def test_gate2_does_not_crash_on_pass(self, pipeline):
        """Old bug: Gate 2 used `reason` before assignment. Now a PASS-level
        Gate 1 (trusted user) still gets Intent + Impact."""
        bus, finals, decisions = pipeline
        get_memory().record_logon("lalit", "127.0.0.1", "interactive (keyboard)")
        await bus.publish(win_event(4720, user_id="lalit", actor="lalit", target_user="x"))
        assert decisions[0].verdict == GateVerdict.PASS
        assert len(finals) == 1

    @pytest.mark.asyncio
    async def test_brute_force_is_not_hidden_by_dedup(self, pipeline):
        """Old bug: Gate 1 de-duplicated similar events for 5 s."""
        bus, finals, _ = pipeline
        for n in range(5, 11):
            await bus.publish(brute(n))
        assert len(finals) == 6
        assert all(d.verdict == GateVerdict.BLOCK for d in finals)

    @pytest.mark.asyncio
    async def test_true_duplicate_record_is_skipped(self, pipeline):
        bus, finals, _ = pipeline
        await bus.publish(brute(5, record_number=777))
        await bus.publish(brute(6, record_number=777))
        assert len(finals) == 1

    @pytest.mark.asyncio
    async def test_brute_force_scores(self, pipeline):
        bus, finals, _ = pipeline
        await bus.publish(brute())
        t = tri(finals[0])
        assert t["trust"]["score"] < 40 and t["intent"]["score"] >= 70
        assert t["risk"]["level"] in ("high", "critical")
        assert finals[0].severity in (Severity.HIGH, Severity.CRITICAL)
        # password guessing -> TEMPORARY restriction (auto re-enabled), not a permanent lock
        assert ResponseAction.RESTRICT_IDENTITY in finals[0].actions
        assert finals[0].metadata["payload"]["user_id"] == "aibootest"

    @pytest.mark.asyncio
    async def test_new_account_made_admin_chain(self, pipeline):
        bus, finals, _ = pipeline
        await bus.publish(win_event(4720, user_id="lalit", actor="lalit", target_user="eve"))
        await bus.publish(win_event(4732, user_id="lalit", actor="lalit", target_user="eve",
                                    group="Administrators", privileged_group=True))
        t = tri(finals[-1])
        assert "attack chain" in texts(t["intent"])
        assert "created only" in texts(t["trust"])
        assert finals[-1].verdict == GateVerdict.BLOCK
        assert finals[-1].metadata["payload"]["user_id"] == "eve"   # act on the new admin

    @pytest.mark.asyncio
    async def test_false_alarm_lowers_next_score(self, pipeline):
        bus, finals, _ = pipeline
        await bus.publish(brute())
        first = tri(finals[-1])["risk"]["score"]
        get_memory().add_feedback("false_alarm", event_id=finals[-1].event_id)
        await bus.publish(brute(6))
        second = tri(finals[-1])
        assert second["risk"]["score"] < first - 8
        assert "false alarm" in texts(second["intent"])

    @pytest.mark.asyncio
    async def test_confirmed_raises_next_score(self, pipeline):
        bus, finals, _ = pipeline
        await bus.publish(win_event(4720, user_id="lalit", actor="lalit", target_user="t1"))
        first = tri(finals[-1])["intent"]["score"]
        get_memory().add_feedback("confirmed", event_id=finals[-1].event_id)
        await bus.publish(win_event(4720, user_id="lalit", actor="lalit", target_user="t2"))
        assert tri(finals[-1])["intent"]["score"] >= first + 10

    @pytest.mark.asyncio
    async def test_test_event_from_dashboard(self, pipeline):
        bus, finals, _ = pipeline
        ev = ThreatEvent(source="dashboard-test", threat_type=ThreatType.NETWORK_INTRUSION,
                         severity=Severity.CRITICAL, payload={"test_event": True, "src_ip": "45.95.147.3"})
        await bus.publish(ev)
        t = tri(finals[0])
        assert t["context"]["test_event"] is True
        assert "Test event" in texts(t["intent"])
        assert "internet address" in texts(t["trust"])


# ------------------------------------------------------ memory on disk
class TestMemoryPersistence:
    def test_survives_restart(self, tmp_path):
        path = str(tmp_path / "trigate_memory.json")
        m = TriGateMemory(path)
        m.record_logon("CORP\\Alice", "10.0.0.5", "network")
        m.record_event("e1", "alice", "brute_force", 70)
        m.add_feedback("false_alarm", event_id="e1")       # saves immediately
        m.set_importance("high")
        m.save(force=True)

        m2 = TriGateMemory(path)                             # "restart"
        assert m2.get_importance() == "high"
        assert m2.user_known("alice") and m2.ip_known_for_user("alice", "10.0.0.5")
        assert m2.feedback_for("brute_force", "alice")["false_alarm"] == 1
        assert m2.count_events(entity="alice", hours=24) == 1

    def test_old_events_are_pruned_after_7_days(self, tmp_path):
        path = str(tmp_path / "m.json")
        m = TriGateMemory(path)
        old = datetime.now(timezone.utc) - timedelta(days=8)
        m.record_event("old", "bob", "brute_force", 50, when=old)
        m.record_event("new", "bob", "brute_force", 50)
        m.save(force=True)
        assert [e["event_id"] for e in TriGateMemory(path).data["events"]] == ["new"]

    def test_corrupt_file_starts_fresh(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text("{not json")
        m = TriGateMemory(str(path))
        assert m.data["events"] == []
        assert os.path.exists(str(path) + ".bad")

    def test_feedback_unknown_decision(self):
        with pytest.raises(KeyError):
            get_memory().add_feedback("false_alarm", event_id="nope")
        with pytest.raises(ValueError):
            get_memory().add_feedback("maybe", pattern="brute_force")

    def test_invalid_importance(self):
        with pytest.raises(ValueError):
            get_memory().set_importance("super")

    def test_computer_accounts_not_recorded(self):
        get_memory().record_logon("GORILLA$", "127.0.0.1", "network")
        assert not get_memory().user_known("gorilla$")


# ------------------------------------------------------ integration bits
class TestIntegration:
    def test_ingestor_remembers_successful_logons(self):
        from log_ingestion.windows_ingestor import WindowsEventIngestor
        ev = ThreatEvent(source="windows_event_log:Security", threat_type=ThreatType.IDENTITY_MISMATCH,
                         severity=Severity.LOW, timestamp=AFTERNOON,
                         payload={"event_id_raw": 4624, "user_id": "lalit", "src_ip": "192.168.1.9",
                                  "logon_type": "network"})
        WindowsEventIngestor._remember_context(ev)
        assert get_memory().ip_known_for_user("lalit", "192.168.1.9")

    @pytest.mark.asyncio
    async def test_bridge_forwards_only_final_decision_with_source(self):
        from core.backend_bridge import DashboardBridge

        class Q:
            def __init__(self):
                self.items = []

            async def add_to_endpoint(self, ep, payload):
                self.items.append((ep, payload))

        b = DashboardBridge.__new__(DashboardBridge)
        b._queue, b._endpoint_id = Q(), "gorilla"
        for gate in (GateLevel.GATE_1, GateLevel.GATE_2, GateLevel.GATE_3):
            await b._on_gate_decision(GateDecision(
                gate=gate, event_id="e1", threat_type=ThreatType.IDENTITY_MISMATCH, severity=Severity.HIGH,
                verdict=GateVerdict.BLOCK, confidence=0.8, reason="r", actions=[],
                metadata={"trigate": {"risk": {"score": 70, "level": "high"}}}))
        assert len(b._queue.items) == 1
        ep, payload = b._queue.items[0]
        assert ep == "gate-decision" and payload["source"] == "gorilla" and payload["gate"] == 3
        json.dumps(payload)                                   # must be JSON-safe

    @pytest.mark.asyncio
    async def test_bridge_tells_backend_if_agent_runs_block_actions_itself(self):
        """PseudoLock approvals: the backend only asks a person to approve when
        the agent does NOT run BLOCK actions itself (auto_response = false)."""
        from core.backend_bridge import DashboardBridge

        class Q:
            def __init__(self):
                self.items = []

            async def add_to_endpoint(self, ep, payload):
                self.items.append(payload)

        for auto in (False, True):
            b = DashboardBridge.__new__(DashboardBridge)
            b._queue, b._endpoint_id = Q(), "gorilla"
            if auto:
                b.auto_response = True
            await b._on_gate_decision(GateDecision(
                gate=GateLevel.GATE_3, event_id="e2", threat_type=ThreatType.IDENTITY_MISMATCH, severity=Severity.HIGH,
                verdict=GateVerdict.BLOCK, confidence=0.8, reason="r", actions=[], metadata={}))
            assert b._queue.items[0]["auto_response"] is auto

    @pytest.mark.asyncio
    async def test_orchestrator_command_handlers(self):
        from core.orchestrator import Orchestrator
        o = Orchestrator.__new__(Orchestrator)
        o.trigate_memory = get_memory()
        assert (await o._cmd_set_importance("", {"importance": "critical"}))["importance"] == "critical"
        with pytest.raises(RuntimeError):
            await o._cmd_set_importance("", {"importance": "bogus"})
        get_memory().record_event("e9", "bob", "brute_force", 60)
        r = await o._cmd_trigate_feedback("e9", {"feedback": "false_alarm", "event_id": "e9"})
        assert r["false_alarm"] == 1 and r["pattern"] == "brute_force"
        with pytest.raises(RuntimeError):
            await o._cmd_trigate_feedback("zz", {"feedback": "false_alarm", "event_id": "zz"})


class TestLocalAccountNames:
    """Windows writes 'THISPC\\user'; cards and the Run button need plain 'user'."""

    def test_local_pc_prefix_removed_from_card(self):
        ctx = build_context(win_event(4732, actor="GORILLA\\lalit", target_user="GORILLA\\aibootest2",
                                      user_id="GORILLA\\lalit", group="Administrators",
                                      privileged_group=True))
        assert ctx["subject"] == "aibootest2" and ctx["entity"] == "lalit"
        recs = recommend(ctx, 70)
        assert any(r["action"] == "revoke_identity" and r["target"] == "aibootest2" for r in recs)

    def test_domain_account_kept(self):
        ctx = build_context(win_event(4720, user_id="CORP\\alice", target_user="CORP\\alice"))
        assert ctx["subject"] == "CORP\\alice"

    def test_pc_name_is_not_a_user(self):
        # 7045 has no user: the ingestor puts the PC name in entity_id
        ctx = build_context(win_event(7045, user_id="unknown", entity_id="GORILLA", device_id="GORILLA",
                                      service_name="AiBooTestSvc", image_path="cmd.exe /c echo"))
        assert ctx["entity"] == ""
        trust, factors = score_trust(ctx)
        assert any("Could not tell which user" in f["text"] for f in factors)

    def test_engine_events_get_names_and_descriptions(self):
        ev = ThreatEvent(source="device_trust_engine", threat_type=ThreatType.DEVICE_HEALTH_FAIL,
                         severity=Severity.HIGH, payload={"device_id": "GORILLA", "reason": "Firewall off"})
        ctx = build_context(ev)
        assert ctx["pattern_label"] == "Device health check failed"
        assert ctx["description"] == "Firewall off"
        assert classify(win_event(None, threat=ThreatType.CONN_BLOCK)).key == "firewall_event"

    def test_generic_description_says_what_it_was(self):
        ev = ThreatEvent(source="x_engine", threat_type=ThreatType.TAILGATING, severity=Severity.LOW,
                         payload={})
        assert build_context(ev)["description"].startswith("Tailgating")
