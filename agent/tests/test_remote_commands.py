"""
Tests for the dashboard -> agent remote command path
(CommandChannel + RealResponseEngine.execute_remote_action).
"""
import os
import subprocess
import sys
import time

import psutil
import pytest

from core.event_bus import EventBus
from core.events import ActionRecord
from core.command_channel import CommandChannel, NAMESPACE
from response.real_response_engine import RealResponseEngine


def _spawn_victim() -> subprocess.Popen:
    """A harmless long-running process that is NOT on the protect list."""
    if os.name == "nt":
        return subprocess.Popen(["ping", "-n", "60", "127.0.0.1"],
                                stdout=subprocess.DEVNULL)
    return subprocess.Popen(["sleep", "60"])


@pytest.fixture
def engine_and_records():
    bus = EventBus()
    records = []

    async def capture(rec: ActionRecord):
        records.append((rec.status, rec.target, dict(rec.metadata)))

    bus.subscribe(ActionRecord, capture)
    return RealResponseEngine(bus, auto_response=False), records


class TestExecuteRemoteAction:
    @pytest.mark.asyncio
    async def test_terminate_by_pid_kills_process_and_publishes_records(self, engine_and_records):
        engine, records = engine_and_records
        victim = _spawn_victim()
        try:
            await engine.execute_remote_action(
                "terminate_process", str(victim.pid), {"cmd_id": "cmd_test_1"}
            )
            time.sleep(0.2)
            assert victim.poll() is not None, "process should be dead"
        finally:
            if victim.poll() is None:
                victim.kill()

        statuses = [r[0] for r in records]
        assert statuses == ["pending", "success"]
        # Real process name + PID shown on the dashboard, linked to the command
        assert f"(PID: {victim.pid})" in records[-1][1]
        assert "unknown" not in records[-1][1]
        assert records[-1][2]["cmd_id"] == "cmd_test_1"
        assert records[-1][2]["remote"] is True

    @pytest.mark.asyncio
    async def test_failure_is_raised_so_dashboard_gets_failed_ack(self, engine_and_records):
        engine, records = engine_and_records
        with pytest.raises(RuntimeError, match="already exited|does not exist"):
            await engine.execute_remote_action("terminate_process", "999999", {})
        assert records[-1][0] == "failed"

    @pytest.mark.asyncio
    async def test_refuses_to_kill_itself(self, engine_and_records):
        engine, _ = engine_and_records
        with pytest.raises(RuntimeError, match="own agent|protect list"):
            await engine.execute_remote_action("terminate_process", str(os.getpid()), {})

    @pytest.mark.asyncio
    async def test_unknown_process_name(self, engine_and_records):
        engine, _ = engine_and_records
        with pytest.raises(RuntimeError, match="No running process named"):
            await engine.execute_remote_action("terminate_process", "definitely-not-running-xyz.exe", {})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["any", "0.0.0.0", "127.0.0.1", "10.0.0.0/8", ""])
    async def test_isolate_rejects_dangerous_targets(self, engine_and_records, bad):
        engine, _ = engine_and_records
        with pytest.raises(RuntimeError):
            await engine.execute_remote_action("isolate_asset", bad, {})

    @pytest.mark.asyncio
    async def test_unknown_action(self, engine_and_records):
        engine, _ = engine_and_records
        with pytest.raises(RuntimeError, match="Unknown action"):
            await engine.execute_remote_action("format_c_drive", "x", {})

    def test_auto_response_off_means_no_auto_terminate(self):
        engine = RealResponseEngine(EventBus(), auto_response=False)
        assert engine._auto_terminate_enabled is False


class _FakeSio:
    def __init__(self):
        self.handlers = {}
        self.emitted = []

    def on(self, event, handler, namespace=None):
        self.handlers[(namespace, event)] = handler

    async def emit(self, event, data, namespace=None):
        self.emitted.append((namespace, event, data))


class _FakeEngine:
    def __init__(self, exc=None):
        self.calls = []
        self.exc = exc

    async def execute_remote_action(self, action, target, params):
        self.calls.append((action, target, params))
        if self.exc:
            raise self.exc


def _channel(engine, allowed=None):
    ch = CommandChannel(engine, "http://localhost:4000", "key", "gorilla", allowed_actions=allowed)
    fake = _FakeSio()
    ch._sio = fake
    ch._register_handlers()
    return ch, fake


class TestCommandChannel:
    def test_handlers_are_bound_to_agent_channel_namespace(self):
        # Root cause of "No agents online": handlers on "/" made the client
        # join the JWT-protected default namespace and get rejected.
        _, fake = _channel(_FakeEngine())
        assert NAMESPACE == "/agent-channel"
        for ev in ("connect", "disconnect", "command"):
            assert (NAMESPACE, ev) in fake.handlers
            assert ("/", ev) not in fake.handlers and (None, ev) not in fake.handlers

    @pytest.mark.asyncio
    async def test_successful_command_acks_received_then_executed(self):
        eng = _FakeEngine()
        ch, fake = _channel(eng, allowed={"terminate_process"})
        await ch._handle_command({"cmd_id": "c1", "action": "terminate_process", "target": "1234"})
        acks = [(e[2]["status"], e[0]) for e in fake.emitted if e[1] == "agent:command-ack"]
        assert acks == [("received", NAMESPACE), ("executed", NAMESPACE)]
        assert eng.calls[0][0:2] == ("terminate_process", "1234")

    @pytest.mark.asyncio
    async def test_engine_error_acks_failed_with_reason(self):
        ch, fake = _channel(_FakeEngine(RuntimeError("Access denied")))
        await ch._handle_command({"cmd_id": "c2", "action": "terminate_process", "target": "1"})
        last = fake.emitted[-1][2]
        assert last["status"] == "failed" and "Access denied" in last["error"]

    @pytest.mark.asyncio
    async def test_disallowed_action_is_rejected_without_running(self):
        eng = _FakeEngine()
        ch, fake = _channel(eng, allowed={"terminate_process"})
        await ch._handle_command({"cmd_id": "c3", "action": "grant_temp_privilege", "target": "bob"})
        assert eng.calls == []
        assert fake.emitted[-1][2]["status"] == "failed"
