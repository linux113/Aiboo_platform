import asyncio

import pytest

from core.event_bus import EventBus
from core.alert_queue import OfflineQueueManager
from response.real_response_engine import RealResponseEngine
from core.command_channel import CommandChannel


class _Event:
    pass


@pytest.mark.asyncio
async def test_suspended_event_bus_delivers_nothing_until_renewed():
    bus = EventBus()
    seen = []

    async def handler(event):
        seen.append(event)

    bus.subscribe(_Event, handler)
    bus.suspended = True
    await bus.publish(_Event())
    assert seen == []

    bus.suspended = False
    event = _Event()
    await bus.publish(event)
    assert seen == [event]


def test_offline_queue_can_pause_delivery_without_losing_queue_state():
    queue = object.__new__(OfflineQueueManager)
    queue._wake = asyncio.Event()
    queue.send_enabled = True

    queue.set_send_enabled(False)
    assert queue.send_enabled is False
    queue.set_send_enabled(True)
    assert queue.send_enabled is True


def test_response_engine_fails_closed_when_company_license_is_inactive(monkeypatch):
    monkeypatch.setenv("AIBOO_AUTO_TERMINATE", "1")
    engine = RealResponseEngine(EventBus(), auto_response=True)
    assert engine._auto_terminate_enabled is True

    engine.set_license_active(False)
    assert engine.license_active is False
    assert engine._auto_terminate_enabled is False

    engine.set_license_active(True, response_actions_enabled=False)
    assert engine.license_active is True
    assert engine.response_actions_enabled is False
    assert engine._auto_terminate_enabled is False

    engine.set_license_active(True, response_actions_enabled=True)
    assert engine.response_actions_enabled is True
    assert engine._auto_terminate_enabled is True


@pytest.mark.asyncio
async def test_tenant_rest_commands_fail_closed_then_execute_and_ack(monkeypatch):
    calls = []

    class Engine:
        async def execute_remote_action(self, action, target, params):
            calls.append((action, target, params))
            return {"message": "completed"}

    channel = CommandChannel(
        Engine(), "http://backend:4000", "aiboo1_key.secret",
        endpoint_id="endpoint-01", allowed_actions={"terminate_process"},
    )
    sent = []
    channel._tenant_request = lambda path, method="GET", payload=None: sent.append((path, method, payload)) or {}
    command = {"cmd_id": "cmd-1", "action": "terminate_process", "target": "123", "params": {}}

    await channel._handle_command(command)
    assert calls == []
    assert sent == []

    channel.set_license_active(True, response_actions_enabled=False)
    await channel._handle_command(command)
    assert calls == []
    assert sent == []

    channel.set_license_active(True, response_actions_enabled=True)
    await channel._handle_command(command)
    assert calls and calls[0][0:2] == ("terminate_process", "123")
    assert len(sent) == 1
    assert sent[0][0] == "/api/agent/commands/cmd-1/ack"
    assert sent[0][2]["status"] == "executed"
    assert sent[0][2]["endpoint_id"] == "endpoint-01"
