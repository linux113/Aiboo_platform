"""Tests for the IsolationAdvisor and offline LLM fallbacks."""
import pytest

from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity, ThreatType,
)
from response.isolation_advisor import IsolationAdvisor
from llm.advisor import heuristic_advice, insights


def make_finding(**overrides):
    base = dict(
        agent_name="CyberThreatAgent",
        event_id="evt_iso_1",
        threat_type=ThreatType.NETWORK_INTRUSION,
        severity=Severity.CRITICAL,
        confidence=0.95,
        summary="SSH brute force from 10.0.0.45",
        actions=[ResponseAction.LOG, ResponseAction.ISOLATE_ASSET, ResponseAction.PSEUDO_LOCK],
        metadata={"src_ip": "10.0.0.45", "user_id": "unknown"},
    )
    base.update(overrides)
    return AgentFinding(**base)


@pytest.mark.asyncio
async def test_suggestion_created_from_critical_finding(event_bus):
    advisor = IsolationAdvisor(event_bus)
    advisor.start()
    await advisor._on_finding(make_finding())
    snaps = advisor.snapshot()
    assert len(snaps) == 1
    s = snaps[0]
    assert s["status"] == "pending"
    assert s["target"] == "10.0.0.45"
    assert "isolate_asset" in s["recommended_actions"]
    assert s["advice_source"] == "offline-rules"  # no API key in tests


@pytest.mark.asyncio
async def test_low_severity_ignored(event_bus):
    advisor = IsolationAdvisor(event_bus)
    await advisor._on_finding(make_finding(severity=Severity.LOW))
    assert advisor.snapshot() == []


@pytest.mark.asyncio
async def test_informational_finding_ignored(event_bus):
    advisor = IsolationAdvisor(event_bus)
    await advisor._on_finding(make_finding(actions=[ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]))
    assert advisor.snapshot() == []


@pytest.mark.asyncio
async def test_dismiss(event_bus):
    advisor = IsolationAdvisor(event_bus)
    await advisor._on_finding(make_finding())
    sid = advisor.snapshot()[0]["id"]
    res = await advisor.dismiss(sid)
    assert res["ok"] is True
    assert advisor.snapshot(status="dismissed")[0]["status"] == "dismissed"


@pytest.mark.asyncio
async def test_execute_simulated_isolation(event_bus):
    advisor = IsolationAdvisor(event_bus)
    advisor.allow_local_actions = False  # force simulation path
    await advisor._on_finding(make_finding())
    sid = advisor.snapshot()[0]["id"]
    res = await advisor.execute(sid)
    assert res["ok"] is True
    s = res["suggestion"]
    assert s["status"] == "executed"
    assert "isolate_asset" in s["executed_actions"]
    assert any("simulated" in str(n) for n in [s.get("notes", "")]) or s["executed_actions"]
    # pseudo_lock should have been re-published to the bus for PseudoLockAgent
    assert "pseudo_lock" in s["executed_actions"]


@pytest.mark.asyncio
async def test_auto_mode_executes_critical(event_bus, monkeypatch):
    advisor = IsolationAdvisor(event_bus)
    advisor.auto_mode = True
    advisor.allow_local_actions = False
    await advisor._on_finding(make_finding())  # critical + 0.95 confidence
    assert advisor.snapshot(status="executed"), "auto mode should execute critical findings"


@pytest.mark.asyncio
async def test_auto_mode_skips_low_confidence(event_bus):
    advisor = IsolationAdvisor(event_bus)
    advisor.auto_mode = True
    await advisor._on_finding(make_finding(confidence=0.5))
    assert advisor.snapshot(status="pending"), "below confidence threshold stays pending"


def test_heuristic_advice_maps_threats():
    actions, text = heuristic_advice("ransomware_prelude", {}, "test")
    assert "isolate_asset" in actions and text
    actions2, text2 = heuristic_advice("unknown_type", {}, "test")
    assert actions2 and text2  # default advice always present


def test_insight_store_bounds():
    for i in range(200):
        insights.add_hypothesis(f"e{i}", f"hyp {i}", f"ent{i}", source="test")
    assert len(insights.hypotheses) <= insights.MAX
