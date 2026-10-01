"""
gates/threat_intel_lookup.py - "is this IP known to be bad?" for Gate 2 (Intent).

Two sources, both optional:

1. Local blocklist file  agent/config/ip_blocklist.txt
   One IP or CIDR range per line (# for comments). Re-read when it changes.
   Works offline - good for testing and for a company's own bad-IP list.

2. Real public feeds (gates/threat_feeds.py): abuse.ch Feodo Tracker,
   Spamhaus DROP, Emerging Threats - downloaded daily, cached on disk.

3. AbuseIPDB (free API, 1000 checks/day) - only if config.ini has
       abuseipdb_key = <your key>
   Only PUBLIC IPs are sent; answers are cached for 6 hours; 3-second timeout
   so a slow internet never blocks the gates.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("ThreatIntelLookup")

DEFAULT_BLOCKLIST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "ip_blocklist.txt")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_SECONDS = 6 * 3600
TIMEOUT_SECONDS = 3.0


@dataclass
class IntelResult:
    malicious: bool
    source: str = ""          # "blocklist" / "feed:<key>" / "abuseipdb"
    score: int = 0            # 0-100 (blocklist hit = 100)
    detail: str = ""


class ThreatIntelLookup:
    def __init__(self, blocklist_path: Optional[str] = DEFAULT_BLOCKLIST,
                 abuseipdb_key: str = "", feeds=None):
        self.blocklist_path = blocklist_path
        self.feeds = feeds                     # FeedManager or None
        self.abuseipdb_key = (abuseipdb_key or "").strip()
        self._networks: list = []
        self._mtime: Optional[float] = None
        self._cache: dict[str, tuple[float, Optional[IntelResult]]] = {}

    # ----------------------------------------------------------- blocklist
    def _reload_blocklist(self) -> None:
        path = self.blocklist_path
        if not path or not os.path.exists(path):
            self._networks, self._mtime = [], None
            return
        mtime = os.path.getmtime(path)
        if mtime == self._mtime:
            return
        nets = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                item = line.split("#", 1)[0].strip()
                if not item:
                    continue
                try:
                    nets.append(ipaddress.ip_network(item, strict=False))
                except ValueError:
                    log.warning("ip_blocklist.txt: ignoring invalid entry %r", item)
        self._networks, self._mtime = nets, mtime
        log.info("Threat intel: %d blocklist entries loaded", len(nets))

    def check_blocklist(self, ip: str) -> Optional[IntelResult]:
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        self._reload_blocklist()
        for net in self._networks:
            if addr.version == net.version and addr in net:
                return IntelResult(True, "blocklist", 100, f"{ip} is on your blocklist ({net})")
        return None

    def check_feeds(self, ip: str) -> Optional[IntelResult]:
        if self.feeds is None:
            return None
        hit = self.feeds.lookup(ip)
        if not hit:
            return None
        key, name, net = hit
        where = f" (range {net})" if "/" in net and not net.endswith(("/32", "/128")) else ""
        return IntelResult(True, f"feed:{key}", 90, f"{ip} is listed by {name}{where}")

    def check_local(self, ip: str) -> Optional[IntelResult]:
        """Instant checks only (blocklist + downloaded feeds) - no network."""
        return self.check_blocklist(ip) or self.check_feeds(ip)

    # ----------------------------------------------------------- abuseipdb
    async def _check_abuseipdb(self, ip: str) -> Optional[IntelResult]:
        if not self.abuseipdb_key:
            return None
        try:
            if not ipaddress.ip_address(ip).is_global:
                return None                      # never send private IPs out
        except ValueError:
            return None
        cached = self._cache.get(ip)
        if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]
        result: Optional[IntelResult] = None
        try:
            import httpx
            async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
                r = await client.get(ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                                     headers={"Key": self.abuseipdb_key, "Accept": "application/json"})
            if r.status_code == 200:
                d = (r.json() or {}).get("data", {}) or {}
                score = int(d.get("abuseConfidenceScore") or 0)
                reports = int(d.get("totalReports") or 0)
                result = IntelResult(score >= 25, "abuseipdb", score,
                                     f"AbuseIPDB: {ip} abuse score {score}% ({reports} reports)")
            else:
                log.warning("AbuseIPDB answered HTTP %s - check abuseipdb_key", r.status_code)
                return None                      # don't cache errors
        except Exception as exc:
            log.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
        self._cache[ip] = (time.monotonic(), result)
        return result

    async def check(self, ip: str) -> Optional[IntelResult]:
        """Blocklist + feeds first (instant), then AbuseIPDB. None = nothing known."""
        if not ip:
            return None
        hit = self.check_local(ip)
        if hit:
            return hit
        try:
            return await asyncio.wait_for(self._check_abuseipdb(ip), TIMEOUT_SECONDS + 1)
        except asyncio.TimeoutError:
            return None


_lookup: Optional[ThreatIntelLookup] = None


def get_threat_intel() -> ThreatIntelLookup:
    global _lookup
    if _lookup is None:
        _lookup = ThreatIntelLookup()
    return _lookup


def configure_threat_intel(blocklist_path: Optional[str] = DEFAULT_BLOCKLIST,
                           abuseipdb_key: str = "", feeds=None) -> ThreatIntelLookup:
    global _lookup
    _lookup = ThreatIntelLookup(blocklist_path, abuseipdb_key, feeds=feeds)
    return _lookup
