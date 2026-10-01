"""
Task 29 tests - incident correlation, behaviour analytics, real threat feeds,
the connection watcher, dynamic access control and compliance checks.
Everything Windows-specific is replaced by fakes, so this runs on Linux.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from core.event_bus import EventBus
from core.events import (
    CorrelatedAlert, GateDecision, GateLevel, ResponseAction, Severity, ThreatEvent, ThreatType,
)
from gates import Gate1Trust, Gate2Intent, Gate3Impact
from gates.gate1_perimeter import build_context
from gates.gate3_adaptive import recommend
from gates.threat_intel_lookup import ThreatIntelLookup, configure_threat_intel
from gates.trigate_memory import TriGateMemory, get_memory, set_memory
from gates.trigate_patterns import configure_settings

AFTERNOON = datetime.now().replace(hour=14, minute=10, second=0, microsecond=0)
NIGHT = datetime.now().replace(hour=3, minute=5, second=0, microsecond=0)


@pytest.fixture(autouse=True)
def fresh(tmp_path):
    set_memory(TriGateMemory(None))
    configure_settings("8-20", "normal")
    configure_threat_intel(blocklist_path=str(tmp_path / "blocklist.txt"), abuseipdb_key="")
    import engines.behaviour_analytics as ba
    ba._engine = None
    yield
    set_memory(TriGateMemory(None))
    configure_threat_intel()
    ba._engine = None


_rec = [0]


def win_event(eid, threat=ThreatType.IDENTITY_MISMATCH, sev=Severity.HIGH, ts=AFTERNOON, **payload):
    _rec[0] += 1
    payload.setdefault("record_number", _rec[0])
    payload.update(event_id_raw=eid, computer_name="GORILLA", log_name="Security")
    return ThreatEvent(source="windows_event_log:Security", threat_type=threat, severity=sev,
                       payload=payload, timestamp=ts)


@pytest.fixture
def pipeline():
    bus = EventBus()
    finals, incidents = [], []
    for g in (Gate1Trust(bus), Gate2Intent(bus), Gate3Impact(bus)):
        g.start()

    async def cap(d):
        if d.gate == GateLevel.GATE_3:
            finals.append(d)

    async def cap_inc(a):
        incidents.append(a)
    bus.subscribe(GateDecision, cap)
    bus.subscribe(CorrelatedAlert, cap_inc)
    return bus, finals, incidents


# =========================================================== correlation
class TestIncidentCorrelator:
    def _item(self, eid, pattern, risk=60, verdict="block", users=("eve",), ip="", ts=0.0):
        from engines.incident_correlator import _Item, stage_of
        keys = {f"user:{u}" for u in users} | ({f"ip:{ip}"} if ip else set())
        return _Item(event_id=eid, ts=ts, pattern=pattern, label=pattern, stage=stage_of(pattern), risk=risk,
                     level="high" if risk >= 55 else "medium", verdict=verdict, keys=frozenset(keys),
                     summary=f"{pattern} for {users}", entity=users[0] if users else "", src_ip=ip)

    def test_attack_chain_two_stages_is_high(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus())
        assert c.add(self._item("a", "brute_force", ts=0)) is None
        alert = c.add(self._item("b", "account_created", risk=45, verdict="hold", ts=60))
        assert isinstance(alert, CorrelatedAlert)
        assert alert.severity == Severity.HIGH
        assert "Credential Access -> Persistence" in alert.description
        assert [f.event_id for f in alert.findings] == ["a", "b"]
        assert alert.incident["users"] == ["eve"]

    def test_chain_grows_same_id_and_becomes_critical(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus())
        c.add(self._item("a", "brute_force", ts=0))
        first = c.add(self._item("b", "account_created", ts=60))
        again = c.add(self._item("c", "admin_group_add", risk=70, ts=120))
        assert again.alert_id == first.alert_id
        assert again.severity == Severity.CRITICAL
        assert len(again.findings) == 3

    def test_unrelated_or_old_events_do_not_link(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus(), window_minutes=60)
        c.add(self._item("a", "brute_force", users=("eve",), ts=0))
        assert c.add(self._item("b", "account_created", users=("bob",), ts=30)) is None
        # same user but outside the 60-minute window
        assert c.add(self._item("c", "service_installed", users=("eve",), ts=3 * 3600)) is None

    def test_shared_ip_links_different_users(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus())
        c.add(self._item("a", "brute_force", users=("eve",), ip="45.95.147.3", ts=0))
        alert = c.add(self._item("b", "threat_intel_alert", users=("bob",), ip="45.95.147.3", ts=10))
        assert alert is not None and "45.95.147.3" in alert.incident["ips"]

    def test_repeated_blocks_same_stage(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus())
        assert c.add(self._item("a", "brute_force", ts=0)) is None
        assert c.add(self._item("b", "brute_force", ts=1)) is None
        alert = c.add(self._item("c", "brute_force", ts=2))
        assert alert is not None and "Repeated" in alert.description

    def test_no_resend_when_nothing_changed(self):
        from engines.incident_correlator import IncidentCorrelator
        c = IncidentCorrelator(EventBus())
        c.add(self._item("a", "brute_force", ts=0))
        assert c.add(self._item("b", "account_created", ts=1)) is not None
        assert c.add(self._item("b", "account_created", ts=2)) is None     # duplicate event id

    @pytest.mark.asyncio
    async def test_real_pipeline_creates_incident(self, pipeline):
        from engines.incident_correlator import IncidentCorrelator
        bus, finals, incidents = pipeline
        IncidentCorrelator(bus).start()
        await bus.publish(win_event(4625, user_id="aibootest", failure_reason="wrong password",
                                    logon_type="interactive (keyboard)", brute_force=True, failed_attempts=6))
        await bus.publish(win_event(4732, user_id="lalit", actor="lalit", target_user="aibootest",
                                    group="Administrators", privileged_group=True))
        assert len(finals) == 2
        assert len(incidents) == 1
        a = incidents[0]
        assert a.threat_type == ThreatType.CORRELATED_ATTACK
        assert "Privilege Escalation" in a.description and "aibootest" in a.description

    @pytest.mark.asyncio
    async def test_pass_decisions_are_ignored(self, pipeline):
        from engines.incident_correlator import IncidentCorrelator
        bus, finals, incidents = pipeline
        IncidentCorrelator(bus).start()
        for _ in range(4):
            await bus.publish(win_event(4672, sev=Severity.LOW, user_id="lalit"))   # admin logon, low risk
        assert incidents == []


# =========================================================== behaviour
class TestBehaviourAnalytics:
    def _engine(self, **kw):
        from engines.behaviour_analytics import BehaviourAnalytics
        return BehaviourAnalytics(memory=get_memory(), min_logons=kw.get("min_logons", 5),
                                  min_days=kw.get("min_days", 2))

    def _learn_days(self, eng, user="lalit", hour=10, n=6, kind="2", ip=""):
        base = datetime.now().astimezone().replace(hour=hour, minute=0, second=0, microsecond=0)
        for i in range(n):
            eng.observe_logon(user, kind, ip, when=base - timedelta(days=i))

    def test_system_and_service_logons_skipped(self):
        eng = self._engine()
        for u in ("SYSTEM", "GORILLA$", "DWM-1", "UMFD-0", "LOCAL SERVICE"):
            assert eng.observe_logon(u, "2") is None
        assert eng.observe_logon("lalit", "5") is None            # service logon type
        assert eng.stats()["users"] == 0

    def test_text_logon_types_from_parser(self):
        from engines.behaviour_analytics import logon_kind_of
        assert logon_kind_of("interactive (keyboard)") == "local"
        assert logon_kind_of("unlock screen") == "local"
        assert logon_kind_of("remote desktop (RDP)") == "remote"
        assert logon_kind_of("network") == "network"
        assert logon_kind_of("service") is None and logon_kind_of("new credentials (RunAs)") is None
        assert logon_kind_of("10") == "remote"

    def test_new_account_used_right_after_creation(self):
        eng = self._engine()
        get_memory().record_event("e1", "lalit", "account_created", 50, subject="aibootest6")
        ev = eng.observe_logon("GORILLA\\aibootest6", "interactive (keyboard)")
        assert ev is not None and ev.threat_type == ThreatType.BEHAVIORAL_ANOMALY
        assert "created" in ev.payload["description"] and ev.payload["user_id"] == "aibootest6"
        # second logon of the same account: no repeat alert
        assert eng.observe_logon("aibootest6", "2") is None

    def test_learning_period_no_alerts(self):
        eng = self._engine(min_logons=50, min_days=10)
        self._learn_days(eng, n=6)
        assert eng.observe_logon("lalit", "10", "10.0.0.9", when=NIGHT.astimezone()) is None

    def test_unusual_hour_after_learning(self):
        eng = self._engine()
        self._learn_days(eng, hour=10, n=8)
        ev = eng.observe_logon("lalit", "2", when=NIGHT.astimezone())
        assert ev is not None
        assert any(r["kind"] == "unusual_hour" for r in ev.payload["behaviour_reasons"])

    def test_first_remote_logon_and_new_ip(self):
        eng = self._engine()
        self._learn_days(eng, hour=11, n=8, kind="3", ip="192.168.1.20")       # usual: network from .20
        ev = eng.observe_logon("lalit", "10", "192.168.1.99",
                               when=datetime.now().astimezone().replace(hour=11))
        kinds = {r["kind"] for r in ev.payload["behaviour_reasons"]}
        assert {"first_remote", "new_ip"} <= kinds
        assert ev.severity == Severity.HIGH

    def test_rate_limited(self):
        eng = self._engine()
        self._learn_days(eng, hour=10, n=8)
        assert eng.observe_logon("lalit", "2", when=NIGHT.astimezone()) is not None
        assert eng.observe_logon("lalit", "2", when=NIGHT.astimezone()) is None

    def test_profile_saved_in_memory_file(self, tmp_path):
        mem = TriGateMemory(str(tmp_path / "mem.json"))
        set_memory(mem)
        eng = self._engine()
        eng.observe_logon("lalit", "2")
        mem.save(force=True)
        data = json.loads((tmp_path / "mem.json").read_text())
        assert data["behaviour"]["lalit"]["total"] == 1
        assert TriGateMemory(str(tmp_path / "mem.json")).data["behaviour"]["lalit"]["hours"][datetime.now().hour] >= 0

    def test_ingestor_hook_and_card_reasons(self):
        from engines.behaviour_analytics import configure_behaviour_analytics
        from log_ingestion.windows_ingestor import WindowsEventIngestor
        configure_behaviour_analytics(True, 5, 2, memory=get_memory())
        get_memory().record_event("e1", "lalit", "account_created", 50, subject="aibootest7")
        ev = WindowsEventIngestor._check_behaviour(win_event(4624, sev=Severity.LOW, user_id="aibootest7",
                                                             logon_type="interactive (keyboard)"))
        assert ev is not None
        ctx = build_context(ev)
        assert ctx["pattern"] == "behavioral_anomaly" and ctx["subject"] == "aibootest7"
        assert ctx["behaviour_reasons"] and "created" in ctx["behaviour_reasons"][0]["text"]
        recs = recommend(ctx, "high")
        assert any(r["action"] == "force_logout" and r["target"] == "aibootest7" for r in recs)
        assert any(r["action"] == "restrict_identity" for r in recs)

    @pytest.mark.asyncio
    async def test_gate2_shows_behaviour_reasons(self, pipeline):
        from engines.behaviour_analytics import BehaviourAnalytics
        bus, finals, _ = pipeline
        get_memory().record_event("e1", "lalit", "account_created", 50, subject="aibootest8")
        ev = BehaviourAnalytics(memory=get_memory()).observe_logon("aibootest8", "2")
        await bus.publish(ev)
        intent = finals[0].metadata["trigate"]["intent"]["factors"]
        assert any("created" in f["text"] and f["points"] >= 20 for f in intent)
        assert finals[0].metadata["trigate"]["context"]["pattern_label"] == "Unusual behaviour"


# =========================================================== threat feeds
FEODO = "# abuse.ch Feodo\n# DstIP\n162.243.103.246\n178.62.3.223\n# END 2 entries\n"
DROP = "; Spamhaus DROP List\n1.10.16.0/20 ; SBL256894\n45.95.82.0/24 ; SBL692989\n"
ET = "101.47.134.74\n102.16.48.130\n"


class TestThreatFeeds:
    def test_parse_formats(self):
        from gates.threat_feeds import parse_feed
        assert [str(n) for n in parse_feed(FEODO)] == ["162.243.103.246/32", "178.62.3.223/32"]
        assert [str(n) for n in parse_feed(DROP)] == ["1.10.16.0/20", "45.95.82.0/24"]
        assert len(parse_feed("junk\n\n300.1.1.1\n" + ET)) == 2

    def test_feed_list_config(self):
        from gates.threat_feeds import parse_feed_list
        assert parse_feed_list(None) == ["feodo", "spamhaus_drop", "et_compromised"]
        assert parse_feed_list("off") == []
        assert parse_feed_list("feodo, nope") == ["feodo"]

    def _manager(self, tmp_path, fail=False):
        from gates.threat_feeds import FEEDS, FeedManager
        texts = {FEEDS["feodo"]["url"]: FEODO, FEEDS["spamhaus_drop"]["url"]: DROP,
                 FEEDS["et_compromised"]["url"]: ET}

        def fetch(url):
            if fail:
                raise OSError("no internet")
            return texts[url]
        return FeedManager(str(tmp_path / "feeds"), None, fetcher=fetch)

    def test_download_cache_and_lookup(self, tmp_path):
        fm = self._manager(tmp_path)
        res = fm.refresh()
        assert set(res.values()) == {"updated"}
        assert fm.lookup("178.62.3.223")[0] == "feodo"
        hit = fm.lookup("45.95.82.77")
        assert hit[0] == "spamhaus_drop" and hit[2] == "45.95.82.0/24"
        assert fm.lookup("8.8.8.8") is None
        assert fm.lookup("192.168.1.5") is None            # private IPs never match
        # second refresh within 24 h uses the cache
        assert set(fm.refresh().values()) == {"cached"}
        # a new manager (agent restart, no internet) loads the cached files
        offline = self._manager(tmp_path, fail=True)
        assert offline.load_cache() == 6
        assert offline.lookup("101.47.134.74")[0] == "et_compromised"
        offline.refresh(force=True)                         # fails but keeps the cache
        assert offline.lookup("101.47.134.74") is not None
        assert offline.status()[0]["error"]

    @pytest.mark.asyncio
    async def test_lookup_and_gate2_factor(self, tmp_path, pipeline):
        fm = self._manager(tmp_path)
        fm.refresh()
        intel = configure_threat_intel(blocklist_path=str(tmp_path / "bl.txt"), feeds=fm)
        r = await intel.check("162.243.103.246")
        assert r.malicious and r.source == "feed:feodo" and "Feodo" in r.detail
        bus, finals, _ = pipeline
        await bus.publish(win_event(4625, user_id="admin", failure_reason="wrong password",
                                    logon_type="network", src_ip="162.243.103.246"))
        factors = finals[0].metadata["trigate"]["intent"]["factors"]
        assert any("Feodo" in f["text"] and f["points"] == 25 for f in factors)

    def test_no_simulated_data_left(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "engines",
                                "threat_intelligence_engine.py"), encoding="utf-8").read()
        for word in ("_simulate", "random.", "DARK_WEB_SAMPLE", "_load_sample_iocs"):
            assert word not in src


class TestConnectionWatcher:
    @pytest.mark.asyncio
    async def test_bad_connection_published_once(self, tmp_path):
        from engines.threat_intelligence_engine import ThreatIntelligenceEngine
        (tmp_path / "bl.txt").write_text("45.95.147.3\n")
        lookup = ThreatIntelLookup(str(tmp_path / "bl.txt"))
        conns = [{"ip": "45.95.147.3", "port": 443, "local_port": 50000, "pid": 4242, "status": "ESTABLISHED"},
                 {"ip": "8.8.8.8", "port": 53, "local_port": 50001, "pid": 77, "status": "ESTABLISHED"}]
        bus = EventBus()
        got = []

        async def cap(e):
            got.append(e)
        bus.subscribe(ThreatEvent, cap)
        eng = ThreatIntelligenceEngine(bus, lookup=lookup, connections=lambda: conns,
                                       proc_info=lambda pid: {"process_name": "evil.exe", "user_id": "GORILLA\\lalit"})
        await eng.scan_once()
        await eng.scan_once()                                # same pair: not again
        assert len(got) == 1
        e = got[0]
        assert e.threat_type == ThreatType.THREAT_INTEL_ALERT
        assert e.payload["src_ip"] == "45.95.147.3" and e.payload["pid"] == 4242
        assert "evil.exe" in e.payload["description"] and "blocklist" in e.payload["description"]
        ctx = build_context(e)
        recs = {r["action"]: r["target"] for r in recommend(ctx, "high")}
        assert recs["block_access"] == "45.95.147.3"
        assert recs["terminate_process"] == "4242"
        assert recs["throttle_segment"] == "45.95.147.3"

    def test_status_without_feeds(self, tmp_path):
        from engines.threat_intelligence_engine import ThreatIntelligenceEngine
        eng = ThreatIntelligenceEngine(EventBus(), lookup=ThreatIntelLookup(str(tmp_path / "x.txt")),
                                       connections=lambda: [])
        st = eng.status()
        assert st["feeds"] == [] and st["scans"] == 0


# =========================================================== access control
class FakeWin:
    def __init__(self, enabled=True, sessions=((1, "lalit"), (2, "eve"), (3, "eve"))):
        self.cmds, self.ps, self.logged_off = [], [], []
        self.enabled = enabled
        self.sessions = list(sessions)
        self.now = 1_000_000.0

    def run(self, cmd, timeout=20):
        self.cmds.append(cmd)
        return SimpleNamespace(returncode=0, stdout="The command completed successfully.", stderr="")

    def powershell(self, script, timeout=30):
        self.ps.append(script)
        return SimpleNamespace(returncode=0, stdout="OK", stderr="")

    def make(self, tmp_path, **kw):
        from response.access_control import WindowsAccessControl
        return WindowsAccessControl(
            str(tmp_path / "ac.json"), run=self.run, powershell=self.powershell,
            sessions=lambda: self.sessions, logoff=lambda sid: self.logged_off.append(sid) or True,
            enabled_check=lambda name: self.enabled, lock=lambda: True, clock=lambda: self.now, **kw)


class TestAccessControl:
    @pytest.fixture(autouse=True)
    def me(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "lalit")
        monkeypatch.setattr("getpass.getuser", lambda: "lalit")

    def test_restrict_logs_off_and_auto_reenables(self, tmp_path):
        w = FakeWin()
        ac = w.make(tmp_path)
        msg = ac.restrict_identity("GORILLA\\eve" if os.environ.get("COMPUTERNAME") == "GORILLA" else "eve", 15)
        assert ["net", "user", "eve", "/active:no"] in w.cmds
        assert w.logged_off == [2, 3] and "2 open session" in msg
        assert json.loads((tmp_path / "ac.json").read_text())["restrictions"]["eve"]["user"] == "eve"
        # restart: state is loaded again
        assert w.make(tmp_path).snapshot()["restrictions"][0]["user"] == "eve"
        w.now += 16 * 60
        done = ac.expire_due()
        assert ["net", "user", "eve", "/active:yes"] in w.cmds and "time is up" in done[0]
        assert ac.snapshot()["restrictions"] == []

    def test_never_self_or_system(self, tmp_path):
        ac = FakeWin().make(tmp_path)
        with pytest.raises(RuntimeError, match="running as"):
            ac.restrict_identity("lalit")
        with pytest.raises(RuntimeError, match="system account"):
            ac.restrict_identity("SYSTEM")
        with pytest.raises(RuntimeError, match="agent runs as"):
            ac.logoff_user("lalit")

    def test_already_disabled_left_alone(self, tmp_path):
        w = FakeWin(enabled=False)
        msg = w.make(tmp_path).restrict_identity("eve")
        assert "already disabled" in msg and w.cmds == []

    def test_restrict_twice_extends(self, tmp_path):
        w = FakeWin()
        ac = w.make(tmp_path)
        ac.restrict_identity("eve", 10)
        assert "already restricted" in ac.restrict_identity("eve", 60)
        assert ac.snapshot()["restrictions"][0]["minutes_left"] == 60

    def test_logoff_no_session(self, tmp_path):
        w = FakeWin(sessions=[(1, "lalit")])
        with pytest.raises(RuntimeError, match="no open session"):
            w.make(tmp_path).logoff_user("eve")

    def test_throttle_and_auto_remove(self, tmp_path):
        w = FakeWin()
        ac = w.make(tmp_path, protected_ips=["10.0.0.5"])
        msg = ac.throttle("203.0.113.0/24", 128, 5)
        assert "128 kbit/s" in msg
        assert "-IPDstPrefixMatchCondition '203.0.113.0/24'" in w.ps[0]
        assert "-ThrottleRateActionBitsPerSecond 128000" in w.ps[0] and "ActiveStore" in w.ps[0]
        w.now += 6 * 60
        ac.expire_due()
        assert "Remove-NetQosPolicy -Name 'AiBoO-Throttle-203-0-113-0-24'" in w.ps[-1]
        assert ac.snapshot()["throttles"] == []

    def test_throttle_safety(self, tmp_path):
        ac = FakeWin().make(tmp_path, protected_ips=["10.0.0.5"])
        with pytest.raises(RuntimeError, match="whole internet"):
            ac.throttle("0.0.0.0/0")
        with pytest.raises(RuntimeError, match="dashboard backend"):
            ac.throttle("10.0.0.0/24")
        with pytest.raises(RuntimeError, match="Not an IP"):
            ac.throttle("server-room")
        assert "64 kbit/s" in ac.throttle("203.0.113.9", 1)          # minimum rate

    @pytest.mark.asyncio
    async def test_remote_commands_use_access_control(self, tmp_path, monkeypatch):
        import response.access_control as acmod
        from response.real_response_engine import RealResponseEngine
        w = FakeWin()
        monkeypatch.setattr(acmod, "_ac", w.make(tmp_path))
        bus = EventBus()
        records = []

        async def cap(r):
            records.append(r)
        from core.events import ActionRecord
        bus.subscribe(ActionRecord, cap)
        eng = RealResponseEngine(bus, auto_response=False)
        await eng.execute_remote_action("restrict_identity", "eve", {"minutes": 5})
        assert records[-1].status == "active" and "5 min" in records[-1].details
        await eng.execute_remote_action("lift_restriction", "eve", {})
        assert ["net", "user", "eve", "/active:yes"] in w.cmds
        await eng.execute_remote_action("force_logout", "eve", {})
        assert "Logged off 'eve'" in records[-1].details
        await eng.execute_remote_action("throttle_segment", "198.51.100.7", {"kbps": 512, "minutes": 2})
        assert records[-1].status == "active" and "198.51.100.7/32" in records[-1].details
        await eng.execute_remote_action("step_up_auth", "eve", {})
        assert "Screen locked" in records[-1].details
        with pytest.raises(RuntimeError, match="running as"):
            await eng.execute_remote_action("restrict_identity", "lalit", {})
        with pytest.raises(RuntimeError, match="IP address or range"):
            await eng.execute_remote_action("throttle_segment", "not-an-ip", {})
        with pytest.raises(RuntimeError, match="network access control"):
            await eng.execute_remote_action("quarantine_device", "pc-7", {})

    def test_remote_allowed_list(self):
        from core.orchestrator import REMOTE_ALLOWED_ACTIONS
        assert {"restrict_identity", "lift_restriction", "throttle_segment", "remove_throttle"} <= REMOTE_ALLOWED_ACTIONS


# =========================================================== compliance
class TestCompliance:
    def _good(self):
        from gates.device_posture import DevicePosture
        return DevicePosture(antivirus_names=["Microsoft Defender"], av_enabled=True, av_up_to_date=True,
                             firewall_off_profiles=[], last_update_days=5, disk_encrypted=True, uac_enabled=True,
                             audit_logon_failure=True, audit_logon_success=True, lockout_threshold=10,
                             min_password_length=12, guest_enabled=False, smb1_enabled=False, rdp_enabled=False)

    def test_parse_extra_posture_fields(self):
        from gates.device_posture import parse_posture, posture_factors
        p = parse_posture({"auditLogon": "Success and Failure", "lockout": "Never", "minPwLen": 0,
                           "guest": False, "smb1": True, "rdpDeny": 0, "uac": 1})
        assert p.audit_logon_failure and p.audit_logon_success
        assert p.lockout_threshold == 0 and p.min_password_length == 0
        assert p.guest_enabled is False and p.smb1_enabled is True and p.rdp_enabled is True
        assert parse_posture({"auditLogon": "No Auditing"}).audit_logon_failure is False
        assert parse_posture({"auditLogon": "Success"}).audit_logon_failure is False
        # extra facts never change device-trust points
        assert posture_factors(p) == posture_factors(parse_posture({"uac": 1}))

    def test_healthy_pc_scores_100(self):
        from gates.compliance_checks import build_report
        r = build_report(self._good(), get_memory(), endpoint="gorilla")
        assert r["score"] == 100 and r["counts"]["fail"] == 0
        iso = r["frameworks"]["ISO 27001:2022"]
        assert iso["failing"] == [] and iso["controls"] >= 10
        assert any("A.8.7" in c for chk in r["checks"] for c in chk["iso27001"])

    def test_weak_pc_fails_with_fixes(self):
        from gates.compliance_checks import build_report
        from gates.device_posture import DevicePosture
        p = DevicePosture(av_enabled=False, firewall_off_profiles=["Public"], last_update_days=90,
                          uac_enabled=False, audit_logon_failure=False, audit_logon_success=False,
                          lockout_threshold=0, min_password_length=0, guest_enabled=True, smb1_enabled=True,
                          rdp_enabled=True)
        get_memory().record_event("x", "lalit", "log_cleared", 64)
        r = build_report(p, get_memory())
        st = {c["id"]: c for c in r["checks"]}
        for cid in ("av_enabled", "firewall_on", "os_updated", "uac_on", "audit_logon", "account_lockout",
                    "password_length", "guest_disabled", "smb1_disabled", "log_integrity"):
            assert st[cid]["status"] == "fail", cid
            assert st[cid]["fix"], cid
        assert st["rdp_exposure"]["status"] == "warn"
        assert st["disk_encrypted"]["status"] == "unknown"           # Windows Home: no penalty
        assert r["score"] < 30
        assert "A.8.15" in r["frameworks"]["ISO 27001:2022"]["failing"]
        assert "PR.PS-04" in r["frameworks"]["NIST CSF 2.0"]["failing"]

    def test_no_posture_is_unknown_not_fail(self):
        from gates.compliance_checks import build_report
        r = build_report(None, None)
        assert r["counts"]["fail"] == 0 and r["score"] == 100        # only the agent check is known

    def test_posture_listener_called(self):
        from gates.device_posture import DevicePosture, PostureMonitor
        seen = []
        m = PostureMonitor(collector=lambda: DevicePosture(uac_enabled=True))
        m.add_listener(seen.append)
        m.refresh()
        assert seen and seen[0].uac_enabled
