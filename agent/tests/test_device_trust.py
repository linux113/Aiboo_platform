"""Device trust in TriGate Gate 1: this PC's health + known / unknown other computers."""

import json
import types
from datetime import datetime

import pytest

from core.events import Severity, ThreatEvent, ThreatType
from gates import device_posture as dp
from gates.device_posture import (
    DevicePosture, PostureMonitor, parse_posture, posture_factors, set_posture_monitor, summary,
)
from gates.gate1_perimeter import build_context, score_trust
from gates.trigate_memory import TriGateMemory, set_memory, get_memory
from gates.trigate_patterns import configure_settings

AFTERNOON = datetime.now().replace(hour=14, minute=10, second=0, microsecond=0)


def healthy(**kw):
    base = dict(av_enabled=True, av_up_to_date=True, antivirus_names=["McAfee"],
                firewall_off_profiles=[], last_update_days=5, disk_encrypted=None, uac_enabled=True)
    base.update(kw)
    return DevicePosture(**base)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("COMPUTERNAME", "GORILLA")        # events below happen on "this PC"
    set_memory(TriGateMemory(None))
    configure_settings("8-20", "normal")
    mon = PostureMonitor(enabled=True, collector=lambda: None)
    set_posture_monitor(mon)
    yield mon
    set_posture_monitor(PostureMonitor(enabled=True, collector=lambda: None))
    set_memory(TriGateMemory(None))


def ev(eid=4720, computer="GORILLA", **payload):
    payload.update(event_id_raw=eid, computer_name=computer, log_name="Security")
    return ThreatEvent(source="windows_event_log:Security", threat_type=ThreatType.IDENTITY_MISMATCH,
                       severity=Severity.HIGH, payload=payload, timestamp=AFTERNOON)


def texts(factors):
    return [f["text"] for f in factors]


# ---------------------------------------------------------------- parsing
class TestParsePosture:
    def test_security_center_third_party_av_on(self):
        # McAfee on (0x1000) + up to date, Defender passive (off)
        p = parse_posture({"av": [{"name": "McAfee", "state": 0x41000}, {"name": "Windows Defender", "state": 0x60100}],
                           "fw": [{"name": "Domain", "on": True}, {"name": "Private", "on": True},
                                  {"name": "Public", "on": True}],
                           "lastUpdateDays": 9, "bitlocker": "Off", "uac": 1})
        assert p.av_enabled is True and p.av_up_to_date is True and p.antivirus_names == ["McAfee"]
        assert p.firewall_off_profiles == [] and p.last_update_days == 9
        assert p.disk_encrypted is False and p.uac_enabled is True

    def test_av_off_outdated_and_single_item_collapsed(self):
        p = parse_posture({"av": {"name": "Windows Defender", "state": 0x60110},
                           "fw": {"name": "Public", "on": False}})
        assert p.av_enabled is False and p.firewall_off_profiles == ["Public"]
        p2 = parse_posture({"av": [{"name": "X", "state": 0x61110}]})
        assert p2.av_enabled is True and p2.av_up_to_date is False

    def test_defender_fallback_and_unknowns(self):
        p = parse_posture({"defender": {"rtp": True, "on": True, "sigAge": 12}})
        assert p.av_enabled is True and p.av_up_to_date is False
        empty = parse_posture({})
        assert empty.known_checks() == 0 and posture_factors(empty) == []


# ---------------------------------------------------------------- scoring
class TestPostureFactors:
    def test_healthy_pc_gets_bonus(self):
        f = posture_factors(healthy())
        assert len(f) == 1 and f[0][0] == dp.P_HEALTHY and "healthy" in f[0][1]

    def test_each_problem(self):
        f = dict((t, p) for p, t in posture_factors(healthy(av_enabled=False)))
        assert any("antivirus" in t for t in f) and dp.P_AV_OFF in f.values()
        f = posture_factors(healthy(firewall_off_profiles=["Public", "Private"]))
        assert f == [(dp.P_FIREWALL_OFF, "Device: Windows Firewall is OFF (Public, Private)")]
        assert posture_factors(healthy(last_update_days=45))[0][0] == dp.P_UPDATES_OLD
        assert posture_factors(healthy(last_update_days=90))[0][0] == dp.P_UPDATES_VERY_OLD
        assert posture_factors(healthy(disk_encrypted=False))[0][0] == dp.P_NOT_ENCRYPTED
        assert posture_factors(healthy(uac_enabled=False))[0][0] == dp.P_UAC_OFF
        assert posture_factors(healthy(av_up_to_date=False))[0][0] == dp.P_AV_OLD

    def test_penalty_is_capped(self):
        bad = healthy(av_enabled=False, firewall_off_profiles=["Public"], last_update_days=200,
                      disk_encrypted=False, uac_enabled=False)
        f = posture_factors(bad)
        assert sum(p for p, _ in f) == dp.DEVICE_PENALTY_CAP and len(f) == 5

    def test_summary_text(self):
        assert "McAfee ON" in summary(healthy()) and "firewall ON" in summary(healthy())
        assert summary(None) == "not checked"


# ---------------------------------------------------------------- Gate 1
class TestGate1DeviceTrust:
    def test_healthy_pc_raises_trust(self, fresh):
        base, _ = score_trust(build_context(ev(user_id="lalit", target_user="aibootest")))
        fresh.set(healthy())
        score, factors = score_trust(build_context(ev(user_id="lalit", target_user="aibootest")))
        assert score == base + dp.P_HEALTHY
        assert any(t.startswith("Device: this PC is healthy") for t in texts(factors))

    def test_firewall_off_lowers_trust(self, fresh):
        fresh.set(healthy(firewall_off_profiles=["Public"]))
        score, factors = score_trust(build_context(ev(user_id="lalit", target_user="aibootest")))
        assert "Device: Windows Firewall is OFF (Public)" in texts(factors)
        assert score == 70 + dp.P_FIREWALL_OFF

    def test_disabled_monitor_gives_no_device_points(self, fresh):
        set_posture_monitor(PostureMonitor(enabled=False, collector=lambda: None))
        dp.get_posture_monitor().set(healthy(av_enabled=False))
        _, factors = score_trust(build_context(ev(user_id="lalit")))
        assert not any(t.startswith("Device:") for t in texts(factors))

    def test_events_from_other_pcs_do_not_use_this_pcs_health(self, fresh):
        # remote-log-sender: event recorded on another PC
        fresh.set(healthy(av_enabled=False))
        _, factors = score_trust(build_context(ev(user_id="bob", computer="OTHER-PC-77")))
        assert not any(t.startswith("Device:") for t in texts(factors))

    def test_unknown_then_known_source_device(self):
        e = ev(4625, user_id="bob", workstation="KALI", failure_reason="wrong password",
               logon_type="network", src_ip="192.168.1.50")
        _, f1 = score_trust(build_context(e))
        assert "Device 'KALI' has never logged in here before (unknown computer)" in texts(f1)
        get_memory().record_logon("alice", "192.168.1.50", "network", workstation="kali.lan")
        _, f2 = score_trust(build_context(e))
        assert "Device 'KALI' has logged in here successfully before" in texts(f2)

    def test_local_keyboard_logon_has_no_device_factor(self):
        e = ev(4625, user_id="bob", workstation="GORILLA", failure_reason="wrong password",
               logon_type="interactive (keyboard)")
        _, f = score_trust(build_context(e))
        assert not any(t.startswith("Device '") for t in texts(f))


# ---------------------------------------------------------------- memory + collector
class TestMemoryAndCollector:
    def test_devices_saved_and_loaded(self, tmp_path):
        path = tmp_path / "m.json"
        m = TriGateMemory(str(path))
        m.record_logon("alice", "10.0.0.5", "network", workstation="LAPTOP-01")
        m.save(force=True)
        m2 = TriGateMemory(str(path))
        assert m2.device_known("laptop-01") and m2.stats()["devices"] == 1

    def test_old_memory_file_without_devices_loads(self, tmp_path):
        path = tmp_path / "old.json"
        path.write_text(json.dumps({"version": 1, "events": [], "logons": {"bob": {"ips": {}}},
                                    "feedback": {}, "decisions": {}}))
        m = TriGateMemory(str(path))
        assert m.user_known("bob") and not m.device_known("x")

    def test_collector_parses_powershell_output(self, monkeypatch):
        monkeypatch.setattr(dp.sys, "platform", "win32")
        out = json.dumps({"av": [{"name": "McAfee", "state": 0x41000}],
                          "fw": [{"name": "Public", "on": False}], "uac": 1})
        monkeypatch.setattr(dp.subprocess, "run",
                            lambda *a, **k: types.SimpleNamespace(stdout=out, stderr="", returncode=0))
        p = dp.collect_windows_posture()
        assert p.av_enabled and p.firewall_off_profiles == ["Public"]

    def test_collector_errors_never_raise(self, monkeypatch):
        monkeypatch.setattr(dp.sys, "platform", "win32")

        def boom(*a, **k):
            raise OSError("powershell missing")
        monkeypatch.setattr(dp.subprocess, "run", boom)
        p = dp.collect_windows_posture()
        assert p.known_checks() == 0 and "powershell" in p.error

    def test_not_windows_returns_none(self, monkeypatch):
        monkeypatch.setattr(dp.sys, "platform", "linux")
        assert dp.collect_windows_posture() is None

    def test_monitor_refresh(self):
        m = PostureMonitor(enabled=True, collector=lambda: healthy())
        assert m.get() is None
        m.refresh()
        assert m.get().av_enabled is True

    def test_configure_from_config_ini_values(self):
        m = dp.configure_device_trust("false", "5", start=False)
        assert m.enabled is False and m.minutes == 5
        m = dp.configure_device_trust(None, "", start=False)
        assert m.enabled is True and m.minutes == 15
