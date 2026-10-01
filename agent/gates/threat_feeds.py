"""
gates/threat_feeds.py - REAL public threat-intel feeds (free, no API key).

Replaces the old simulated feeds / fake "dark web" alerts. Downloaded once a
day, cached on disk (so it also works offline after the first download) and
checked instantly in memory:

  feodo           abuse.ch Feodo Tracker - botnet command-and-control servers
                  https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  spamhaus_drop   Spamhaus DROP - hijacked / criminal networks (IP ranges)
                  https://www.spamhaus.org/drop/drop.txt
  et_compromised  Emerging Threats (Proofpoint) - known compromised hosts
                  https://rules.emergingthreats.net/blockrules/compromised-ips.txt

config.ini (optional):
    threat_feeds         = feodo, spamhaus_drop, et_compromised   # or: off
    threat_feed_hours    = 24        # how often to download again

Used by Gate 2 (threat intel factor) and by the connection watcher
(ThreatIntelligenceEngine), which checks this PC's live outbound connections.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
import urllib.request
from typing import Any, Callable, Optional

log = logging.getLogger("ThreatFeeds")

FEEDS: dict[str, dict] = {
    "feodo": {
        "name": "abuse.ch Feodo Tracker (botnet command servers)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    },
    "spamhaus_drop": {
        "name": "Spamhaus DROP (hijacked / criminal networks)",
        "url": "https://www.spamhaus.org/drop/drop.txt",
    },
    "et_compromised": {
        "name": "Emerging Threats compromised hosts",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    },
}
DEFAULT_FEEDS = ("feodo", "spamhaus_drop", "et_compromised")
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT = 30
USER_AGENT = "AiBoO-Agent/2.0 (+threat-intel)"


def parse_feed(text: str) -> list:
    """IP / CIDR per line; '#' and ';' start comments (Spamhaus: '1.2.3.0/24 ; SBL123')."""
    nets = []
    for line in (text or "").splitlines():
        item = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not item:
            continue
        item = item.split()[0]
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def parse_feed_list(value: Any) -> list[str]:
    v = str(value if value is not None else ",".join(DEFAULT_FEEDS)).strip().lower()
    if v in ("", "off", "none", "false", "0", "no"):
        return []
    if v in ("all", "on", "true", "yes", "1"):
        return list(DEFAULT_FEEDS)
    out = []
    for part in v.replace(";", ",").split(","):
        k = part.strip()
        if k in FEEDS and k not in out:
            out.append(k)
        elif k:
            log.warning("threat_feeds: unknown feed %r (known: %s)", k, ", ".join(FEEDS))
    return out


def _download(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:           # nosec - fixed https URLs
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("feed too large")
    return data.decode("utf-8", errors="ignore")


class _Index:
    """Fast lookup: exact IPs in a set, ranges bucketed by first octet."""

    def __init__(self, nets: list):
        self.exact: set = set()
        self.buckets: dict[int, list] = {}
        self.wide: list = []
        for n in nets:
            if n.num_addresses == 1:
                self.exact.add(n.network_address)
            elif n.version == 4 and n.prefixlen >= 8:
                self.buckets.setdefault(int(n.network_address) >> 24, []).append(n)
            else:
                self.wide.append(n)
        self.count = len(nets)

    def find(self, addr) -> Optional[Any]:
        if addr in self.exact:
            return ipaddress.ip_network(addr)
        if addr.version == 4:
            for n in self.buckets.get(int(addr) >> 24, ()):
                if addr in n:
                    return n
        for n in self.wide:
            if n.version == addr.version and addr in n:
                return n
        return None


class FeedManager:
    def __init__(self, cache_dir: Optional[str], feeds: Optional[list] = None,
                 refresh_hours: float = 24, fetcher: Callable[[str], str] = _download):
        self.cache_dir = cache_dir
        self.feeds = list(DEFAULT_FEEDS if feeds is None else feeds)
        self.refresh_seconds = max(1.0, float(refresh_hours or 24)) * 3600
        self._fetch = fetcher
        self._index: dict[str, _Index] = {}
        self._meta: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ cache io
    def _path(self, key: str) -> Optional[str]:
        return os.path.join(self.cache_dir, f"{key}.txt") if self.cache_dir else None

    def _meta_path(self) -> Optional[str]:
        return os.path.join(self.cache_dir, "feeds_meta.json") if self.cache_dir else None

    def _save_meta(self) -> None:
        path = self._meta_path()
        if not path:
            return
        try:
            with open(path + ".tmp", "w", encoding="utf-8") as fh:
                json.dump(self._meta, fh, indent=1)
            os.replace(path + ".tmp", path)
        except OSError as exc:
            log.debug("feed meta not saved: %s", exc)

    def load_cache(self) -> int:
        """Load cached feed files (no network). Returns total entries."""
        if not self.cache_dir:
            return 0
        try:
            with open(self._meta_path(), "r", encoding="utf-8") as fh:
                self._meta = json.load(fh) or {}
        except (OSError, ValueError):
            self._meta = {}
        total = 0
        for key in self.feeds:
            path = self._path(key)
            if path and os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        nets = parse_feed(fh.read())
                    with self._lock:
                        self._index[key] = _Index(nets)
                    total += len(nets)
                except OSError:
                    pass
        return total

    def _age_seconds(self, key: str) -> Optional[float]:
        ts = (self._meta.get(key) or {}).get("updated_epoch")
        return None if not ts else time.time() - float(ts)

    def refresh(self, force: bool = False) -> dict:
        """Download feeds that are older than refresh_hours. Keeps the old copy
        if a download fails. Returns {feed: 'updated'|'cached'|'error: ..'}."""
        result = {}
        for key in self.feeds:
            age = self._age_seconds(key)
            if not force and age is not None and age < self.refresh_seconds and key in self._index:
                result[key] = "cached"
                continue
            info = FEEDS[key]
            try:
                text = self._fetch(info["url"])
                nets = parse_feed(text)
                if not nets:
                    raise ValueError("no IP entries in download")
                path = self._path(key)
                if path:
                    os.makedirs(self.cache_dir, exist_ok=True)
                    with open(path + ".tmp", "w", encoding="utf-8") as fh:
                        fh.write(text)
                    os.replace(path + ".tmp", path)
                with self._lock:
                    self._index[key] = _Index(nets)
                self._meta[key] = {"updated_epoch": time.time(),
                                   "updated": time.strftime("%Y-%m-%d %H:%M"), "count": len(nets), "error": ""}
                result[key] = "updated"
                log.info("Threat feed %s: %d entries downloaded", key, len(nets))
            except Exception as exc:
                m = self._meta.setdefault(key, {})
                m["error"] = str(exc)[:200]
                m["last_attempt"] = time.strftime("%Y-%m-%d %H:%M")
                result[key] = f"error: {exc}"
                log.warning("Threat feed %s download failed (%s) - using %s", key, exc,
                            "cached copy" if key in self._index else "nothing yet")
        self._save_meta()
        return result

    # -------------------------------------------------------------- lookup
    def lookup(self, ip: Any) -> Optional[tuple[str, str, str]]:
        """(feed_key, feed_name, matching_range) or None."""
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        if not addr.is_global:
            return None
        with self._lock:
            items = list(self._index.items())
        for key, idx in items:
            n = idx.find(addr)
            if n is not None:
                return key, FEEDS[key]["name"], str(n)
        return None

    def total_entries(self) -> int:
        with self._lock:
            return sum(i.count for i in self._index.values())

    def status(self) -> list[dict]:
        out = []
        for key in self.feeds:
            m = self._meta.get(key) or {}
            idx = self._index.get(key)
            out.append({"key": key, "name": FEEDS[key]["name"], "url": FEEDS[key]["url"],
                        "entries": idx.count if idx else 0, "updated": m.get("updated", ""),
                        "error": m.get("error", "")})
        return out

    # ---------------------------------------------------------- background
    def start(self) -> None:
        if self._thread is not None or not self.feeds:
            return

        def loop():
            n = self.load_cache()
            if n:
                log.info("Threat feeds: %d cached entries loaded", n)
            if self._stop.wait(3):
                return
            while not self._stop.is_set():
                try:
                    self.refresh()
                except Exception as exc:          # never kill the thread
                    log.debug("feed refresh failed: %s", exc)
                self._stop.wait(3600)             # check hourly, download when stale

        self._thread = threading.Thread(target=loop, name="ThreatFeeds", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
