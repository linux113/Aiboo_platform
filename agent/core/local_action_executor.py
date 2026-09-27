"""
agent/core/local_action_executor.py — Executes kill/isolate/revoke actions locally.
"""
import asyncio
import logging
from .event_bus import EventBus
from .executor import kill_process, isolate_machine, revoke_isolation
from .alert_queue import OfflineQueueManager

log = logging.getLogger("LocalActionExecutor")

class LocalActionExecutor:
    def __init__(self, bus: EventBus, config: dict):
        self.bus = bus
        self.config = config
        self._subscribers = []

    async def start(self):
        # Subscribe to high-severity alert events
        self._subscribers.append(
            await self.bus.subscribe("alert.high", self._handle_alert)
        )
        self._subscribers.append(
            await self.bus.subscribe("alert.critical", self._handle_alert)
        )
        log.info("LocalActionExecutor started – listening for high/critical alerts")

    async def stop(self):
        for sub in self._subscribers:
            await self.bus.unsubscribe(sub)
        log.info("LocalActionExecutor stopped")

    async def _handle_alert(self, alert: dict):
        """Called when a high/critical alert is published."""
        action = alert.get("action")
        pid = alert.get("pid")
        log.info("LocalActionExecutor: alert action=%s pid=%s", action, pid)

        # Execute locally
        if action == "kill" and pid:
            kill_process(pid)
        elif action == "isolate":
            isolate_machine(self.config.get("server_ip", "192.168.1.100"))
        elif action == "revoke":
            revoke_isolation()
        else:
            log.debug("No local action taken for alert: %s", alert)

        # Queue the alert for cloud forwarding (offline queue)
        queue = OfflineQueueManager.get_instance()
        alert_payload = {
            "source": self.config.get("endpoint_name", "Unknown"),
            "severity": alert.get("severity", "HIGH"),
            "engine": alert.get("engine", "LocalActionExecutor"),
            "action_taken": action,
            "event": alert.get("event", {})
        }
        await queue.add(alert_payload)