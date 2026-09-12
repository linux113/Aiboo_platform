"""
process_killer.py — Local response: terminates flagged processes.

Safety: DISABLED by default. Enable via config.ini  [AIBOO] process_killer_enabled = true
or environment variable AIBOO_PROCESS_KILLER_ENABLED=1.
The kill list comes from config.ini [AIBOO] kill_list (comma-separated) or
AIBOO_KILL_LIST env var. Never ships with a hardcoded demo kill list.
"""
import asyncio
import logging
import os
import configparser

import psutil

from .executor import kill_process

log = logging.getLogger("ProcessKiller")


def _load_settings() -> tuple[bool, list[str]]:
    """Read (enabled, kill_list) from config.ini / environment."""
    enabled = os.environ.get("AIBOO_PROCESS_KILLER_ENABLED", "").strip().lower() in ("1", "true", "yes")
    kill_list_raw = os.environ.get("AIBOO_KILL_LIST", "").strip()

    try:
        base_dir = os.getcwd()
        cp = configparser.ConfigParser()
        if cp.read(os.path.join(base_dir, "config.ini")) and cp.has_section("AIBOO"):
            enabled = enabled or cp.get("AIBOO", "process_killer_enabled", fallback="").strip().lower() in ("1", "true", "yes")
            kill_list_raw = kill_list_raw or cp.get("AIBOO", "kill_list", fallback="").strip()
    except Exception:
        pass

    kill_list = [p.strip().lower() for p in kill_list_raw.split(",") if p.strip()]
    return enabled, kill_list


class ProcessKiller:
    def __init__(self, interval: float = 3.0, enabled: bool | None = None,
                 bad_processes: list[str] | None = None):
        self.interval = interval
        cfg_enabled, cfg_list = _load_settings()
        self.enabled = cfg_enabled if enabled is None else enabled
        self.bad_processes = (cfg_list if bad_processes is None else bad_processes)
        self._running = False
        self._poll_task = None
        if self.enabled and not self.bad_processes:
            log.warning("ProcessKiller enabled but kill_list is empty — nothing will be terminated.")
            self.enabled = False

    async def start(self):
        if not self.enabled:
            log.info("ProcessKiller DISABLED (set process_killer_enabled=true in config.ini to enable)")
            return
        self._running = True
        self._poll_task = asyncio.create_task(self._poll())
        log.info("ProcessKiller started – watching for: %s", ", ".join(self.bad_processes))

    async def stop(self):
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        log.info("ProcessKiller stopped")

    async def _poll(self):
        while self._running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        name = (proc.info['name'] or "").lower()
                        if name in self.bad_processes:
                            pid = proc.info['pid']
                            log.warning("ProcessKiller terminating flagged process: %s (PID: %d)", name, pid)
                            kill_process(pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                await asyncio.sleep(self.interval)
            except Exception as e:
                log.error("Poll error: %s", e)
                await asyncio.sleep(5)
