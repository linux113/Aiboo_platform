"""
engines/threat_intelligence_engine.py — Threat Intelligence Engine

Ingests and maintains threat intelligence from multiple sources:
- STIX/TAXII feeds (simulated or via API)
- Dark web monitoring (NLP-based credential/ransomware chatter)
- Live IOCs (IPs, domains, file hashes, email addresses)
- TTP mapping to MITRE ATT&CK

Publishes ThreatEvent when relevant IOCs match incoming events
or when dark web mentions are detected.

Part of Layer 2: Detection & Intelligence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Set, Tuple, Any
from collections import defaultdict

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity,
    AgentFinding
)

log = logging.getLogger("ThreatIntelEngine")

# ============================================
# Constants & Configuration
# ============================================

# Threat intelligence feed refresh interval (seconds)
FEED_REFRESH_INTERVAL = 3600  # 1 hour

# Dark web monitoring interval
DARK_WEB_MONITOR_INTERVAL = 1800  # 30 minutes

# Default severity for IOC matches based on confidence
IOC_SEVERITY_MAP = {
    "high": Severity.CRITICAL,
    "medium": Severity.HIGH,
    "low": Severity.MEDIUM,
}

# MITRE ATT&CK mapping for common signatures/tactics
MITRE_ATTACK_MAPPING = {
    "T1046": {"name": "Network Service Scanning", "tactic": "Discovery"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1003": {"name": "Credential Dumping", "tactic": "Credential Access"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1484": {"name": "Domain Policy Modification", "tactic": "Defense Evasion"},
}

# Known threat actor groups (simplified)
THREAT_ACTORS = {
    "APT29": {"aliases": ["Cozy Bear"], "motivation": "espionage"},
    "APT28": {"aliases": ["Fancy Bear"], "motivation": "espionage"},
    "Lazarus": {"aliases": ["HIDDEN COBRA"], "motivation": "financial, espionage"},
    "FIN7": {"aliases": ["Carbanak"], "motivation": "financial"},
}

# Sample dark web indicators (simulated)
DARK_WEB_SAMPLE_INDICATORS = [
    {"type": "credential", "domain": "example.com", "username": "admin", "source": "pastebin"},
    {"type": "ransomware", "victim": "example_org", "group": "LockBit", "timestamp": "2025-01-01"},
]


@dataclass
class IntelligenceItem:
    """Represents a threat intelligence item."""
    indicator_type: str  # "ip", "domain", "hash", "email", "url"
    value: str
    confidence: float  # 0.0 - 1.0
    severity: Severity
    sources: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK IDs
    actor: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DarkWebMention:
    """Represents a dark web mention."""
    type: str  # "credential", "ransomware", "malware", "data_breach"
    content: str
    source: str
    timestamp: datetime
    confidence: float
    entities: Dict[str, str] = field(default_factory=dict)


class ThreatIntelligenceEngine:
    """
    Threat Intelligence Engine.
    Maintains a repository of IOCs, matches them against incoming events,
    monitors dark web sources, and publishes alerts.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._iocs: Dict[str, IntelligenceItem] = {}  # key: indicator_value (unique)
        self._iocs_by_type: Dict[str, Set[str]] = defaultdict(set)  # type -> set of values
        self._dark_web_mentions: List[DarkWebMention] = []
        self._running = False

        # Background tasks
        self._feed_refresh_task: Optional[asyncio.Task] = None
        self._dark_web_task: Optional[asyncio.Task] = None

        # Organization domain (for dark web monitoring)
        self._organization_domain = "example.com"  # Should be configurable

        # Configuration (could be external)
        self._config = {
            "feed_refresh_interval": FEED_REFRESH_INTERVAL,
            "dark_web_monitor_interval": DARK_WEB_MONITOR_INTERVAL,
            "organization_domain": "example.com",
            "ioc_ttl_seconds": 86400 * 30,  # 30 days
            "stix_feed_urls": [
                # In production, these would be real TAXII endpoints
                "https://example.com/stix/feed.json",
                "https://other-feed.com/indicators.xml",
            ],
            "dark_web_sources": ["pastebin", "dark_web_forums", "ransomware_leak_sites"],
        }

        # Initialize with some default IOCs for demo
        self._load_sample_iocs()

        log.info("ThreatIntelligenceEngine initialized")

    def start(self) -> None:
        """Start the engine: subscribe to events and start background tasks."""
        self.bus.subscribe(ThreatEvent, self._on_threat_event)
        self.bus.subscribe(AgentFinding, self._on_agent_finding)

        self._running = True
        self._feed_refresh_task = asyncio.create_task(self._refresh_feed_loop())
        self._dark_web_task = asyncio.create_task(self._dark_web_monitor_loop())

        log.info("ThreatIntelligenceEngine started — monitoring threat intel")

    # ============================================
    # IOC Management
    # ============================================

    def add_ioc(self, indicator_type: str, value: str, confidence: float,
                severity: Severity, sources: List[str] = None,
                ttps: List[str] = None, actor: str = None,
                expires_in_hours: int = None) -> None:
        """Add a new intelligence item to the repository."""
        if value in self._iocs:
            # Update existing
            item = self._iocs[value]
            item.confidence = max(item.confidence, confidence)
            item.severity = max(item.severity, severity, key=lambda s: s.weight)
            if sources:
                item.sources.extend(sources)
            if ttps:
                item.ttps.extend(ttps)
            if actor:
                item.actor = actor
            if expires_in_hours:
                item.expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            return

        expires_at = None
        if expires_in_hours:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        item = IntelligenceItem(
            indicator_type=indicator_type,
            value=value,
            confidence=confidence,
            severity=severity,
            sources=sources or [],
            ttps=ttps or [],
            actor=actor,
            expires_at=expires_at,
        )
        self._iocs[value] = item
        self._iocs_by_type[indicator_type].add(value)
        log.debug(f"Added IOC: {indicator_type} {value} (conf={confidence})")

    def remove_ioc(self, value: str) -> bool:
        """Remove an IOC."""
        if value in self._iocs:
            item = self._iocs[value]
            self._iocs_by_type[item.indicator_type].discard(value)
            del self._iocs[value]
            return True
        return False

    def get_ioc(self, value: str) -> Optional[IntelligenceItem]:
        """Retrieve an IOC by value."""
        return self._iocs.get(value)

    def get_iocs_by_type(self, indicator_type: str) -> List[IntelligenceItem]:
        """Get all IOCs of a given type."""
        return [self._iocs[v] for v in self._iocs_by_type.get(indicator_type, []) if v in self._iocs]

    def _load_sample_iocs(self):
        """Load sample IOCs for demonstration."""
        sample_iocs = [
            ("ip", "192.168.99.100", 0.9, Severity.CRITICAL, ["Internal threat feed"], ["T1078", "T1190"], "APT29"),
            ("ip", "10.10.10.50", 0.7, Severity.HIGH, ["External feed"], ["T1046"], None),
            ("domain", "malware-c2.example.com", 0.95, Severity.CRITICAL, ["ThreatFox"], ["T1071"], "FIN7"),
            ("hash", "d41d8cd98f00b204e9800998ecf8427e", 0.8, Severity.HIGH, ["VirusTotal"], ["T1059"], None),
            ("email", "malicious@phish.com", 0.6, Severity.MEDIUM, ["Abuse.ch"], ["T1566"], None),
            ("url", "http://evil.com/exploit", 0.85, Severity.HIGH, ["AlienVault"], ["T1190"], "Lazarus"),
        ]
        for ioc in sample_iocs:
            self.add_ioc(*ioc)

    # ============================================
    # IOC Matching
    # ============================================

    def match_event_against_iocs(self, event: ThreatEvent) -> List[IntelligenceItem]:
        """
        Match event payload against known IOCs.
        Returns a list of matching IntelligenceItems.
        """
        p = event.payload
        matches = []

        # Check IPs
        src_ip = p.get("src_ip")
        dst_ip = p.get("dst_ip")
        for ip in [src_ip, dst_ip]:
            if ip and ip in self._iocs:
                matches.append(self._iocs[ip])

        # Check domain (from payload or extracted from URLs)
        domain = p.get("domain") or p.get("dst_domain")
        if domain and domain in self._iocs:
            matches.append(self._iocs[domain])
        # Also check for domain in URL
        url = p.get("url")
        if url:
            # Extract domain from URL
            import urllib.parse
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname
                if hostname and hostname in self._iocs:
                    matches.append(self._iocs[hostname])
            except:
                pass

        # Check file hashes
        file_hash = p.get("file_hash") or p.get("hash")
        if file_hash and file_hash in self._iocs:
            matches.append(self._iocs[file_hash])

        # Check email addresses
        email = p.get("email") or p.get("sender")
        if email and email in self._iocs:
            matches.append(self._iocs[email])

        # Check for signature-based IOC (e.g., signature names)
        signature = p.get("signature")
        if signature:
            # If signature matches a known pattern (e.g., a threat actor name)
            for actor_name in THREAT_ACTORS.keys():
                if actor_name.lower() in signature.lower():
                    # Could create a temporary IOC match
                    # For simplicity, we'll skip adding a match here
                    pass

        return matches

    # ============================================
    # Event Handlers
    # ============================================

    async def _on_threat_event(self, event: ThreatEvent) -> None:
        """Process incoming threat events for IOC matching."""
        matches = self.match_event_against_iocs(event)
        if not matches:
            return

        # Determine highest severity from matches
        max_sev = max(matches, key=lambda i: i.severity.weight).severity
        # Aggregate confidence
        avg_conf = sum(i.confidence for i in matches) / len(matches)

        # Build payload for alert
        ioc_details = [
            {
                "type": i.indicator_type,
                "value": i.value,
                "confidence": i.confidence,
                "ttps": i.ttps,
                "actor": i.actor,
            }
            for i in matches
        ]

        alert_event = ThreatEvent(
            source="ThreatIntelligenceEngine",
            threat_type=ThreatType.THREAT_INTEL_ALERT,
            severity=max_sev,
            payload={
                "matched_iocs": ioc_details,
                "original_event": {
                    "event_id": event.event_id,
                    "source": event.source,
                    "threat_type": event.threat_type.value,
                    "payload": event.payload,
                },
                "avg_confidence": avg_conf,
                "ttps_identified": list(set(t for i in matches for t in i.ttps)),
                "threat_actors": list(set(i.actor for i in matches if i.actor)),
            }
        )
        await self.bus.publish(alert_event)
        log.warning(
            f"Threat intel match: {len(matches)} IOC(s) matched event {event.event_id}"
            f" (severity: {max_sev.value})"
        )

    async def _on_agent_finding(self, finding: AgentFinding) -> None:
        """Learn from agent findings to possibly enrich IOCs."""
        # If an agent reports a high-confidence threat, we might add its indicators to our IOC list.
        if finding.confidence > 0.8 and finding.severity in (Severity.HIGH, Severity.CRITICAL):
            # Extract potential indicators from metadata
            meta = finding.metadata
            if meta.get("src_ip"):
                self.add_ioc(
                    "ip", meta["src_ip"], confidence=0.7,
                    severity=Severity.HIGH,
                    sources=[f"Agent:{finding.agent_name}"]
                )
            if meta.get("dst_ip"):
                self.add_ioc(
                    "ip", meta["dst_ip"], confidence=0.6,
                    severity=Severity.MEDIUM,
                    sources=[f"Agent:{finding.agent_name}"]
                )

    # ============================================
    # Feed Refresh (STIX/TAXII simulation)
    # ============================================

    async def _refresh_feed_loop(self) -> None:
        """Periodically refresh threat intelligence feeds."""
        while self._running:
            await asyncio.sleep(self._config["feed_refresh_interval"])
            try:
                # In production, this would fetch from actual TAXII endpoints
                # For now, simulate by adding some random IOCs
                new_iocs = self._simulate_feed_update()
                for ioc in new_iocs:
                    self.add_ioc(**ioc)
                if new_iocs:
                    log.info(f"Refreshed threat feed: added {len(new_iocs)} new IOCs")
            except Exception as e:
                log.error(f"Feed refresh error: {e}")

    def _simulate_feed_update(self) -> List[Dict]:
        """Simulate fetching new IOCs from an external feed."""
        # In production, this would parse STIX/TAXII JSON/XML
        # For demo, generate a few random indicators
        import random
        import string

        def random_ip():
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

        def random_hash():
            return ''.join(random.choices(string.hexdigits.lower(), k=32))

        iocs = []
        # Add one or two random IOCs
        for _ in range(random.randint(0, 2)):
            ioc_type = random.choice(["ip", "domain", "hash", "email"])
            if ioc_type == "ip":
                value = random_ip()
            elif ioc_type == "domain":
                value = f"malware-{''.join(random.choices(string.ascii_lowercase, k=6))}.com"
            elif ioc_type == "hash":
                value = random_hash()
            else:  # email
                value = f"bad-{''.join(random.choices(string.ascii_lowercase, k=6))}@phish.com"

            # Assign TTPs randomly
            ttps = random.sample(list(MITRE_ATTACK_MAPPING.keys()), k=random.randint(0, 2))

            iocs.append({
                "indicator_type": ioc_type,
                "value": value,
                "confidence": round(random.uniform(0.5, 0.95), 2),
                "severity": random.choice([Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]),
                "sources": ["Simulated STIX feed"],
                "ttps": ttps,
                "actor": random.choice(list(THREAT_ACTORS.keys())) if random.random() > 0.5 else None,
            })
        return iocs

    # ============================================
    # Dark Web Monitoring (Simulated)
    # ============================================

    async def _dark_web_monitor_loop(self) -> None:
        """Periodically check dark web sources for mentions of the organization."""
        while self._running:
            await asyncio.sleep(self._config["dark_web_monitor_interval"])
            try:
                mentions = self._simulate_dark_web_check()
                for mention in mentions:
                    await self._process_dark_web_mention(mention)
            except Exception as e:
                log.error(f"Dark web monitor error: {e}")

    def _simulate_dark_web_check(self) -> List[DarkWebMention]:
        """Simulate checking dark web sources (pastebin, forums, ransomware sites)."""
        # In production, this would use web scraping, API calls, or data feeds
        # For demo, occasionally generate a mention
        import random
        mentions = []

        # Probability of generating a mention (e.g., 20% chance each run)
        if random.random() < 0.2:
            mention_type = random.choice(["credential", "ransomware", "data_breach"])
            if mention_type == "credential":
                entities = {
                    "domain": self._config["organization_domain"],
                    "username": random.choice(["admin", "user1", "root", "service_account"]),
                    "source": random.choice(["pastebin", "hackforums", "breachforums"]),
                }
                content = f"Credentials for {entities['domain']} user {entities['username']} posted on {entities['source']}"
            elif mention_type == "ransomware":
                groups = ["LockBit", "Clop", "REvil", "BlackCat", "Hive"]
                entities = {
                    "group": random.choice(groups),
                    "victim_domain": self._config["organization_domain"],
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                }
                content = f"Ransomware group {entities['group']} claims attack on {entities['victim_domain']}"
            else:  # data_breach
                entities = {
                    "domain": self._config["organization_domain"],
                    "record_count": str(random.randint(100, 10000)),
                    "source": random.choice(["dark web forum", "leak site"]),
                }
                content = f"Data breach: {entities['record_count']} records from {entities['domain']} leaked on {entities['source']}"

            mention = DarkWebMention(
                type=mention_type,
                content=content,
                source=entities.get("source", "unknown"),
                timestamp=datetime.now(timezone.utc),
                confidence=random.uniform(0.5, 0.9),
                entities=entities,
            )
            mentions.append(mention)
        return mentions

    async def _process_dark_web_mention(self, mention: DarkWebMention) -> None:
        """Process a dark web mention and publish alert if relevant."""
        # Determine severity based on mention type and confidence
        if mention.type == "ransomware" and mention.confidence > 0.7:
            severity = Severity.CRITICAL
        elif mention.type == "credential" and mention.confidence > 0.6:
            severity = Severity.HIGH
        elif mention.type == "data_breach":
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        # Only alert if confidence is high enough
        if mention.confidence < 0.4:
            return

        # Check if the organization domain is mentioned
        org_domain = self._config["organization_domain"]
        if org_domain not in mention.content and not any(org_domain in v for v in mention.entities.values()):
            # If not directly mentioning our org, maybe still relevant? For simplicity, require mention
            return

        # Build payload
        payload = {
            "mention_type": mention.type,
            "content": mention.content,
            "source": mention.source,
            "timestamp": mention.timestamp.isoformat(),
            "confidence": mention.confidence,
            "entities": mention.entities,
        }

        alert_event = ThreatEvent(
            source="ThreatIntelligenceEngine:DarkWeb",
            threat_type=ThreatType.THREAT_INTEL_ALERT,
            severity=severity,
            payload=payload,
            timestamp=mention.timestamp,
        )
        await self.bus.publish(alert_event)
        log.warning(f"Dark web mention detected: {mention.type} - {mention.content[:100]}")

    # ============================================
    # Public Query Methods
    # ============================================

    def get_all_iocs(self) -> List[IntelligenceItem]:
        """Get all active IOCs."""
        # Filter out expired
        now = datetime.now(timezone.utc)
        active = []
        for item in self._iocs.values():
            if item.expires_at is None or item.expires_at > now:
                active.append(item)
        return active

    def get_iocs_by_source(self, source: str) -> List[IntelligenceItem]:
        """Get IOCs from a specific source."""
        return [i for i in self._iocs.values() if source in i.sources]

    def get_threat_actors(self) -> Dict[str, Dict]:
        """Get known threat actors."""
        return THREAT_ACTORS.copy()

    def get_mitre_attack_mapping(self) -> Dict[str, Dict]:
        """Get MITRE ATT&CK mapping."""
        return MITRE_ATTACK_MAPPING.copy()

    # ============================================
    # Shutdown
    # ============================================

    def stop(self) -> None:
        """Stop the engine and background tasks."""
        self._running = False
        if self._feed_refresh_task:
            self._feed_refresh_task.cancel()
        if self._dark_web_task:
            self._dark_web_task.cancel()
        log.info("ThreatIntelligenceEngine stopped")