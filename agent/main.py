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
from api.ingestion_api import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

log = logging.getLogger("main")


def ensure_endpoint_config():
    """
    Check if config.ini exists and has a valid endpoint_name.
    If not, prompt the user (only if interactive) or auto-set to hostname.
    No Unicode/emoji characters – plain ASCII only.
    """
    # Determine the base directory (works for both script and frozen .exe)
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.getcwd()
    config_path = os.path.join(base_dir, 'config.ini')

    # Load existing config or create a new one
    config = configparser.ConfigParser()
    if os.path.exists(config_path):
        config.read(config_path)
    if not config.has_section('AIBOO'):
        config['AIBOO'] = {}

    # Set default values if missing
    defaults = {
        'remote_url': 'https://your-ngrok-url.ngrok-free.dev',
        'api_key': 'dev-key-change-in-production',
        'server_ip': '192.168.1.100',
        'log_level': 'INFO',
    }
    for key, val in defaults.items():
        if not config.has_option('AIBOO', key):
            config['AIBOO'][key] = val

    # Get current endpoint name
    current_name = config.get('AIBOO', 'endpoint_name', fallback='').strip()

    # If empty or default placeholder, we need to set one
    if not current_name or current_name.lower() in ('unknown', 'unknown_pc', ''):
        # Check if we are running interactively (has a terminal)
        if sys.stdin.isatty():
            # Interactive prompt – safe to use print/input
            print("\n" + "=" * 50)
            print("  Welcome to AiBoO Agent!")
            print("=" * 50)
            print("Please enter a unique name for this endpoint (e.g., 'Alice_Laptop'):")
            new_name = input("> ").strip()
            if not new_name:
                new_name = socket.gethostname()
                print(f"No input provided. Using hostname: {new_name}")
            config['AIBOO']['endpoint_name'] = new_name
            with open(config_path, 'w') as f:
                config.write(f)
            print(f"[OK] Endpoint name set to: {new_name}")
            print(f"Config saved to: {config_path}\n")
        else:
            # Running as a service (no console) – auto-set to hostname
            hostname = socket.gethostname()
            config['AIBOO']['endpoint_name'] = hostname
            with open(config_path, 'w') as f:
                config.write(f)
            log.info(f"Service mode: auto-set endpoint name to {hostname}")
    else:
        log.info(f"Using existing endpoint name: {current_name}")


def run_api_server(event_bus):
    """Run the FastAPI server in a background thread."""
    log.info("[INFO] Starting API server on http://0.0.0.0:8000")
    app = create_app(event_bus)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


async def main():
    # Ensure endpoint name is configured before anything else
    ensure_endpoint_config()

    bus = EventBus()

    api_thread = threading.Thread(target=run_api_server, args=(bus,), daemon=True)
    api_thread.start()

    await asyncio.sleep(2)

    orchestrator = Orchestrator(bus)
    await orchestrator.start()

    log.info("[STARTUP] AiBoO started — API on port 8000, orchestrator active")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        log.warning("Shutting down...")
    finally:
        await orchestrator.shutdown()
        log.info("Shutdown complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")