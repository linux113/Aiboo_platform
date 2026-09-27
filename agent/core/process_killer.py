import asyncio
import psutil
import logging
from .executor import kill_process

log = logging.getLogger("ProcessKiller")

class ProcessKiller:
    def __init__(self, interval: float = 3.0):
        self.interval = interval
        self._running = False
        self._poll_task = None

    async def start(self):
        self._running = True
        self._poll_task = asyncio.create_task(self._poll())
        log.info("ProcessKiller started – polling for malicious processes")

    async def stop(self):
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        log.info("ProcessKiller stopped")

    async def _poll(self):
        # List of process names to kill (case-insensitive)
        bad_processes = ["notepad.exe", "calc.exe"]
        while self._running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        name = proc.info['name'].lower()
                        if name in bad_processes:
                            pid = proc.info['pid']
                            log.info("Polling found malicious: %s (PID: %d)", name, pid)
                            kill_process(pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                await asyncio.sleep(self.interval)
            except Exception as e:
                log.error("Poll error: %s", e)
                await asyncio.sleep(5)