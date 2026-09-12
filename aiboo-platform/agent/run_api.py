"""
Run AiBoO with FastAPI Ingestion Layer ONLY
No Windows Event Log ingestion - just API endpoint for external agents
"""

import asyncio
import logging
import signal
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(__file__))

import uvicorn

from core.event_bus import EventBus
from core.events import ThreatEvent, ThreatType, Severity
from api.ingestion_api import create_app
from core.config import config

logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s \u2014 %(message)s",
    datefmt="%H:%M:%S",
)

logging.getLogger("WindowsIngestor").setLevel(logging.WARNING)
logging.getLogger("Gate1.Perimeter").setLevel(logging.INFO)
logging.getLogger("CyberThreatAgent").setLevel(logging.INFO)

log = logging.getLogger("runner")

event_bus = EventBus()
_shutdown_requested = False


def handle_signal(signum, frame):
    global _shutdown_requested
    if _shutdown_requested:
        log.warning("Forced exit")
        sys.exit(1)
    _shutdown_requested = True
    log.warning("Received signal %s, shutting down gracefully...", signum)


class SimplePrintAgent:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.name = "PrintAgent"
        bus.subscribe(ThreatEvent, self.handle)

    async def handle(self, event: ThreatEvent):
        log.info(
            "Agent received event: id=%s source=%s type=%s severity=%s message=%s",
            event.event_id, event.source, event.threat_type.value,
            event.severity.value, event.payload.get('message', 'No message')
        )


def run_api_server():
    app = create_app(event_bus)
    log.info("API Server starting on http://localhost:%s", config.api_port)
    uvicorn.run(app, host="0.0.0.0", port=config.api_port, log_level="warning")


async def run_agents():
    print_agent = SimplePrintAgent(event_bus)
    log.info("PrintAgent active")
    try:
        while not _shutdown_requested:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.warning("Shutdown requested")


async def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()

    await run_agents()

    log.info("Shutdown complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
