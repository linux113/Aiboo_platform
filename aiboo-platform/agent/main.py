"""
AiBoO — Unified Runner (Orchestrator + API Server)
"""

import asyncio
import logging
import sys
import os
import threading
import socket
import configparser

sys.path.insert(0, os.path.dirname(__file__))

import uvicorn
from core.orchestrator import Orchestrator
from core.event_bus import EventBus
from core.config import config
from api.ingestion_api import create_app


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

log = logging.getLogger("main")


def ensure_endpoint_config():
    """
    Ensure AiBoO has a valid endpoint name and backend URL.

    Behaviour:
      - config.ini lives next to this script (works for script AND frozen exe).
      - Missing options are filled with sane defaults:
          remote_url -> NODE_BACKEND env or http://localhost:4000
          api_key    -> AGENT_API_KEY env or dev-key-change-in-production
      - Missing endpoint name is auto-set to the hostname.
        Interactive naming ONLY happens when AIBOO_INTERACTIVE=1 is set
        (never blocks services / start-all.bat).
    """

    # Determine the base directory.
    # For normal Python execution this is the agent directory.
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    config_path = os.path.join(base_dir, "config.ini")

    # Load existing configuration.
    agent_config = configparser.ConfigParser()

    if os.path.exists(config_path):
        agent_config.read(config_path)

    if not agent_config.has_section("AIBOO"):
        agent_config["AIBOO"] = {}

    # Default configuration (env-aware so Docker/services need no edits).
    defaults = {
        "remote_url": os.environ.get("NODE_BACKEND", "http://localhost:4000"),
        "api_key": os.environ.get("AGENT_API_KEY", "dev-key-change-in-production"),
        "server_ip": "127.0.0.1",
        "log_level": "INFO",
    }

    for key, value in defaults.items():
        if not agent_config.has_option("AIBOO", key):
            agent_config["AIBOO"][key] = value

    # Get endpoint name.
    current_name = agent_config.get(
        "AIBOO",
        "endpoint_name",
        fallback=""
    ).strip()

    # Configure endpoint if missing.
    if not current_name or current_name.lower() in (
        "unknown",
        "unknown_pc",
        "unknown-pc",
    ):

        hostname = socket.gethostname()

        # Only ask the user when explicitly requested.
        interactive_mode = (
            sys.stdin.isatty()
            and os.environ.get("AIBOO_INTERACTIVE") == "1"
        )

        if interactive_mode:

            print("\n" + "=" * 50)
            print("  Welcome to AiBoO Agent!")
            print("=" * 50)
            print(
                "Please enter a unique name for this endpoint "
                "(e.g., 'Alice_Laptop'):"
            )

            try:
                new_name = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                new_name = ""

            if not new_name:
                new_name = hostname

            endpoint_name = new_name

        else:
            # Automatic service/start-all.bat mode.
            endpoint_name = hostname

            log.info(
                "Service mode: auto-set endpoint name to %s",
                endpoint_name
            )

        agent_config["AIBOO"]["endpoint_name"] = endpoint_name

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                agent_config.write(f)

            log.info(
                "Endpoint configuration saved: %s",
                config_path
            )

        except OSError as exc:
            log.error(
                "Could not save endpoint configuration: %s",
                exc
            )

    else:
        log.info(
            "Using existing endpoint name: %s",
            current_name
        )

    # Surface the resolved backend target so misconfiguration is obvious.
    log.info(
        "Backend target: %s (api_key %s)",
        agent_config.get("AIBOO", "remote_url"),
        "set" if agent_config.get("AIBOO", "api_key") else "MISSING",
    )


def run_api_server(event_bus):
    """Run the FastAPI server in a background thread."""

    log.info(
        "[INFO] Starting API server on http://%s:%s",
        config.api_host,
        config.api_port,
    )

    app = create_app(event_bus)

    uvicorn.run(
        app,
        host=config.api_host,
        port=config.api_port,
        log_level="info",
    )


async def main():

    # Configure endpoint before starting services.
    ensure_endpoint_config()

    # Create event bus.
    bus = EventBus()

    # Start FastAPI server.
    api_thread = threading.Thread(
        target=run_api_server,
        args=(bus,),
        daemon=True,
    )

    api_thread.start()

    # Give API server time to initialize.
    await asyncio.sleep(2)

    # Start orchestrator.
    orchestrator = Orchestrator(bus)

    await orchestrator.start()

    log.info(
        "[STARTUP] AiBoO started — API on port %s, orchestrator active",
        config.api_port,
    )

    try:
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        log.warning("Shutting down...")

    finally:

        try:
            await orchestrator.shutdown()
        except Exception as exc:
            log.error(
                "Error while shutting down orchestrator: %s",
                exc,
            )

        log.info("Shutdown complete.")


if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        log.warning("Interrupted by user.")

    except Exception:
        log.exception("AiBoO Agent failed to start.")
        sys.exit(1)
