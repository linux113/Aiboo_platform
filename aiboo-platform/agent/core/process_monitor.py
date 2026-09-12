import psutil
import asyncio
import logging
from .event_bus import EventBus

log = logging.getLogger("ProcessMonitor")

class ProcessMonitor:
    def __init__(self, bus: EventBus, interval: float = 3.0):
        self.bus = bus
        self.interval = interval
        self._running = False
        self._task = None
        self._seen_pids = set()

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._poll())
        log.info("ProcessMonitor started (polling every %.1f s)", self.interval)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("ProcessMonitor stopped")

    async def _poll(self):
        while self._running:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._seen_pids
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        event = {
                            "type": "process_start",
                            "pid": pid,
                            "name": proc.name(),
                            "cmdline": ' '.join(proc.cmdline()),
                            "parent_pid": proc.ppid(),
                            "parent_name": proc.parent().name() if proc.parent() else "N/A",
                            "timestamp": asyncio.get_event_loop().time()
                        }
                        await self.bus.publish("process.start", event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self._seen_pids = current_pids
            except Exception as e:
                log.error("ProcessMonitor poll error: %s", e)
            await asyncio.sleep(self.interval)