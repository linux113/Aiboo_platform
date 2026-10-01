"""
engines/threat_intelligence_engine.py - REAL threat-intel matching.

The old version loaded made-up sample IOCs, "simulated" random feed updates
and randomly invented "dark web" / "ransomware group claims attack" alerts.
All of that is gone. What it does now:

  * Every `interval` seconds (default 30) it lists this PC's LIVE network
    connections (psutil) and checks every public remote IP against
      - your own blocklist  agent/config/ip_blocklist.txt
      - the real public feeds (gates/threat_feeds.py): abuse.ch Feodo
        Tracker, Spamhaus DROP, Emerging Threats compromised hosts
  * A match publishes a THREAT_INTEL_ALERT ThreatEvent that goes through the
    TriGate like every other event. The card shows which program (name +
    PID) talked to which bad IP and which list it is on, with one-click
    "Block IP" and "Kill process".
  * Each (IP, process) pair is reported at most once per hour.

AbuseIPDB is NOT used here (it has a daily limit); Gate 2 still uses it for
the source IP of Windows events when abuseipdb_key is set.

config.ini (optional):
    intel_connection_scan    = true
    intel_scan_seconds       = 30
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Callable, Optional

from core.event_bus import EventBus
from core.events import Severity, ThreatEvent, ThreatType

log = logging.getLogger("ThreatIntelligence")

REPORT_EVERY_SECONDS = 3600
_STATUSES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT"}


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def list_connections() -> list[dict]:
    """[{ip, port, local_port, pid, status}] for remote public endpoints."""
    import psutil
    out = []
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or c.status not in _STATUSES:
            continue
        ip = c.raddr.ip
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if not _public(ip):
            continue
        out.append({"ip": ip, "port": c.raddr.port, "local_port": c.laddr.port if c.laddr else None,
                    "pid": c.pid, "status": c.status})
    return out


def process_info(pid: Optional[int]) -> dict:
    if not pid:
        return {}
    try:
        import psutil
        p = psutil.Process(pid)
        info = {"process_name": p.name()}
        try:
            info["process_path"] = p.exe()
        except Exception:
            pass
        try:
            info["user_id"] = p.username()
        except Exception:
            pass
        return info
    except Exception:
        return {}


class ThreatIntelligenceEngine:
    def __init__(self, bus: EventBus, interval: float = 30, enabled: bool = True,
                 lookup=None, connections: Callable[[], list] = list_connections,
                 proc_info: Callable[[Optional[int]], dict] = process_info, clock=time.time):
        self.bus = bus
        self.interval = max(5.0, float(interval or 30))
        self.enabled = enabled
        self._lookup = lookup
        self._connections = connections
        self._proc_info = proc_info
        self._clock = clock
        self._reported: dict[tuple, float] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self.scans = 0
        self.matches = 0
        self.last_error = ""

    @property
    def lookup(self):
        if self._lookup is None:
            from gates.threat_intel_lookup import get_threat_intel
            return get_threat_intel()
        return self._lookup

    def start(self) -> None:
        if not self.enabled:
            log.info("Threat intel connection scan OFF (intel_connection_scan = false)")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        log.info("Threat intelligence online - live connections checked every %ds against "
                 "blocklist + public feeds (no simulated data)", int(self.interval))

    async def _loop(self) -> None:
        await asyncio.sleep(10)
        while self._running:
            try:
                await self.scan_once()
            except Exception as exc:              # never stop scanning
                self.last_error = str(exc)[:200]
                log.debug("connection scan failed: %s", exc)
            await asyncio.sleep(self.interval)

    async def scan_once(self) -> list[ThreatEvent]:
        conns = await asyncio.to_thread(self._connections)
        self.scans += 1
        events = []
        now = self._clock()
        seen_this_scan = set()
        for c in conns:
            ip = c.get("ip")
            key = (ip, c.get("pid"))
            if key in seen_this_scan:
                continue
            seen_this_scan.add(key)
            if now - self._reported.get(key, 0) < REPORT_EVERY_SECONDS:
                continue
            hit = self.lookup.check_local(ip)
            if not hit or not hit.malicious:
                continue
            self._reported[key] = now
            proc = await asyncio.to_thread(self._proc_info, c.get("pid"))
            name = proc.get("process_name") or "unknown program"
            pid = c.get("pid")
            feed = hit.source.split(":", 1)[1] if hit.source.startswith("feed:") else hit.source
            severity = Severity.CRITICAL if feed == "feodo" else Severity.HIGH
            desc = (f"This PC is connected to {ip}:{c.get('port')} - {hit.detail}. "
                    f"Program: {name}" + (f" (PID {pid})" if pid else ""))
            event = ThreatEvent(
                source="ThreatIntelligence",
                threat_type=ThreatType.THREAT_INTEL_ALERT,
                severity=severity,
                payload={
                    "src_ip": ip,                    # the bad IP (Block IP acts on it)
                    "dst_ip": ip,
                    "dst_port": c.get("port"),
                    "local_port": c.get("local_port"),
                    "connection_state": c.get("status"),
                    "pid": pid,
                    "process_name": name,
                    "process_path": proc.get("process_path", ""),
                    "user_id": proc.get("user_id", ""),
                    "threat_feed": feed,
                    "intel_detail": hit.detail,
                    "description": desc[:300],
                    "direction": "outbound",
                },
            )
            self.matches += 1
            log.warning("THREAT INTEL MATCH: %s", desc)
            await self.bus.publish(event)
            events.append(event)
        # forget old reports
        for k in [k for k, t in self._reported.items() if now - t > 2 * REPORT_EVERY_SECONDS]:
            self._reported.pop(k, None)
        return events

    def status(self) -> dict:
        feeds = getattr(self.lookup, "feeds", None)
        return {
            "connection_scan": self.enabled, "interval_seconds": int(self.interval),
            "scans": self.scans, "matches": self.matches, "last_error": self.last_error,
            "feeds": feeds.status() if feeds is not None else [],
            "feed_entries": feeds.total_entries() if feeds is not None else 0,
            "abuseipdb": bool(getattr(self.lookup, "abuseipdb_key", "")),
        }

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
