"""
agents/cyber_threat_agent.py — Cyber Threat Detection Agent

Analyses network intrusion signals, anomalous traffic patterns,
signature-based detections, and endpoint telemetry.
Also includes memory scanning for ransomware and malicious processes,
plus encrypted traffic analysis and honeypot detection.
"""

from __future__ import annotations

import asyncio
import psutil
import hashlib
import re
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime, timezone

from core.base_agent import BaseAgent
from core.event_bus import EventBus
from core.events import (
    AgentFinding, ResponseAction, Severity,
    ThreatEvent, ThreatType,
)


# Packet-rate thresholds (packets/sec) mapped to severity uplift
_RATE_THRESHOLDS: dict[int, Severity] = {
    10_000: Severity.CRITICAL,
    5_000:  Severity.HIGH,
    1_000:  Severity.MEDIUM,
}

# Known high-risk signatures
_CRITICAL_SIGNATURES = {
    "SSH_BRUTE_FORCE",
    "SQL_INJECTION",
    "RCE_EXPLOIT",
    "RANSOMWARE_C2",
    "DATA_EXFIL",
}

# Memory threat patterns
_MEMORY_THREAT_PATTERNS = {
    "ransomware": ["ransom", "crypt", "encrypt", "decrypt", "locker", "bitlocker", "wallet"],
    "suspicious_processes": ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil"],
    "malicious_powershell": ["-enc", "-encodedcommand", "bypass", "hidden", "downloadstring", "webclient", "invoke-expression", "iex", "invoke-command"],
    "suspicious_memory": [b"MZ", b"powershell", b"cmd.exe", b"rundll32"]
}

# Memory scan interval (seconds)
_MEMORY_SCAN_INTERVAL = 30

# ---- NEW: Encrypted traffic analysis thresholds ----
_ENCRYPTED_TRAFFIC = {
    "data_volume_threshold_gb": 10,          # >10GB in a session is suspicious
    "suspicious_ports": {443, 993, 995, 22, 3389},  # ports often used for encrypted tunnels
    "off_hours_threshold": 22,               # after 10 PM
    "early_hours_threshold": 6,              # before 6 AM
}

# ---- NEW: Honeypot detection ----
# Simulated honeypot IP ranges (CIDR notation) - in production, this would be a dynamic list
_HONEYPOT_IPS = {
    "192.168.99.0/24",
    "10.10.10.0/24",
    "172.16.99.0/24",
}


@dataclass
class MemoryThreat:
    """Represents a memory-based threat detected by CyberAgent"""
    pid: int
    process_name: str
    threat_type: str
    confidence: float
    details: str


class CyberThreatAgent(BaseAgent):
    def __init__(self, bus: EventBus) -> None:
        super().__init__("CyberThreatAgent", bus)
        self._memory_scan_running = False
        self._scanned_processes = {}  # Track process hashes to avoid repeated alerts

    def can_handle(self, event: ThreatEvent) -> bool:
        return event.threat_type in (
            ThreatType.NETWORK_INTRUSION,
            ThreatType.ANOMALOUS_BEHAVIOR,
            ThreatType.INSIDER_THREAT,
        )

    # ============================================================
    # Memory scanning (existing)
    # ============================================================

    async def start_memory_scanning(self) -> None:
        """Start background memory scanning for ransomware and malicious processes"""
        self._memory_scan_running = True
        self.log.info("Memory scanning activated - scanning every %d seconds", _MEMORY_SCAN_INTERVAL)

        while self._memory_scan_running:
            try:
                threats = await self._scan_memory_for_threats()
                for threat in threats:
                    memory_event = ThreatEvent(
                        source="memory_scanner",
                        threat_type=ThreatType.NETWORK_INTRUSION,
                        severity=Severity.CRITICAL if threat.threat_type == "RANSOMWARE" else Severity.HIGH,
                        payload={
                            "pid": threat.pid,
                            "process_name": threat.process_name,
                            "memory_threat_type": threat.threat_type,
                            "details": threat.details,
                            "signature": f"MEMORY_{threat.threat_type}"
                        }
                    )
                    finding = await self.analyse(memory_event)
                    if finding:
                        await self.bus.publish(finding)

                await asyncio.sleep(_MEMORY_SCAN_INTERVAL)

            except Exception as e:
                self.log.error(f"Memory scan error: {e}")
                await asyncio.sleep(5)

    async def _scan_memory_for_threats(self) -> List[MemoryThreat]:
        threats = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info']):
            try:
                proc_fingerprint = f"{proc.info['pid']}_{proc.info['name']}"
                name_threat = self._check_process_name(proc)
                if name_threat and proc_fingerprint not in self._scanned_processes:
                    threats.append(name_threat)
                    self._scanned_processes[proc_fingerprint] = name_threat.threat_type

                cmdline_threat = self._check_command_line(proc)
                if cmdline_threat and proc_fingerprint not in self._scanned_processes:
                    threats.append(cmdline_threat)
                    self._scanned_processes[proc_fingerprint] = cmdline_threat.threat_type

                memory_threat = await self._check_memory_usage(proc)
                if memory_threat and proc_fingerprint not in self._scanned_processes:
                    threats.append(memory_threat)
                    self._scanned_processes[proc_fingerprint] = memory_threat.threat_type

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if len(self._scanned_processes) > 1000:
            self._scanned_processes.clear()

        return threats

    def _check_process_name(self, proc) -> Optional[MemoryThreat]:
        name = proc.info['name'].lower() if proc.info['name'] else ""
        if not name:
            return None

        for pattern in _MEMORY_THREAT_PATTERNS["ransomware"]:
            if pattern in name:
                return MemoryThreat(
                    pid=proc.info['pid'],
                    process_name=name,
                    threat_type="RANSOMWARE",
                    confidence=0.90,
                    details=f"Process name matches ransomware pattern: {pattern}"
                )

        for susp in _MEMORY_THREAT_PATTERNS["suspicious_processes"]:
            if susp in name:
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
                for pattern in _MEMORY_THREAT_PATTERNS["malicious_powershell"]:
                    if pattern in cmdline:
                        return MemoryThreat(
                            pid=proc.info['pid'],
                            process_name=name,
                            threat_type="SUSPICIOUS_PROCESS",
                            confidence=0.85,
                            details=f"Suspicious {susp} with malicious arguments: {pattern}"
                        )
        return None

    def _check_command_line(self, proc) -> Optional[MemoryThreat]:
        cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
        if not cmdline:
            return None

        if "powershell" in cmdline:
            base64_count = cmdline.count('-enc') + cmdline.count('-encodedcommand')
            if base64_count > 0:
                base64_match = re.search(r'-enc\s+([A-Za-z0-9+/=]+)', cmdline)
                if base64_match:
                    b64_string = base64_match.group(1)
                    if len(b64_string) > 50:
                        return MemoryThreat(
                            pid=proc.info['pid'],
                            process_name=proc.info['name'],
                            threat_type="ENCODED_POWERSHELL",
                            confidence=0.80,
                            details=f"PowerShell with long encoded command ({len(b64_string)} chars)"
                        )

        download_patterns = ["downloadstring", "webclient", "invoke-webrequest", "curl", "wget"]
        for pattern in download_patterns:
            if pattern in cmdline:
                return MemoryThreat(
                    pid=proc.info['pid'],
                    process_name=proc.info['name'],
                    threat_type="SUSPICIOUS_DOWNLOAD",
                    confidence=0.75,
                    details=f"Process attempting to download file: {pattern}"
                )
        return None

    async def _check_memory_usage(self, proc) -> Optional[MemoryThreat]:
        try:
            memory_info = proc.info['memory_info']
            if memory_info and memory_info.rss > 500 * 1024 * 1024:
                return MemoryThreat(
                    pid=proc.info['pid'],
                    process_name=proc.info['name'],
                    threat_type="HIGH_MEMORY_USAGE",
                    confidence=0.60,
                    details=f"Process using {memory_info.rss / 1024 / 1024:.0f}MB memory"
                )
        except:
            pass
        return None

    async def _terminate_process(self, pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            self.log.warning(f"Terminating suspicious process: {proc_name} (PID: {pid})")
            proc.terminate()
            await asyncio.sleep(2)
            if proc.is_running():
                proc.kill()
            self.log.warning(f"Process terminated: {proc_name}")
            return True
        except Exception as e:
            self.log.error(f"Failed to terminate process {pid}: {e}")
            return False

    # ============================================================
    # NEW: Encrypted Traffic Analysis
    # ============================================================

    def _analyze_encrypted_traffic(self, p: dict) -> dict:
        """
        Analyze encrypted traffic patterns without decrypting contents.
        Returns dict with: is_anomalous, risk_score, reason, actions.
        """
        result = {
            "is_anomalous": False,
            "risk_score": 0.0,
            "reason": "Traffic pattern normal",
            "actions": []
        }

        # Check data volume
        data_volume = p.get("data_volume_gb", 0)
        if data_volume > _ENCRYPTED_TRAFFIC["data_volume_threshold_gb"]:
            result["is_anomalous"] = True
            result["risk_score"] = 0.7
            result["reason"] = f"Encrypted data volume too high: {data_volume:.1f}GB"
            result["actions"].append(ResponseAction.ISOLATE_ASSET)

        # Check time of day
        now = datetime.now(timezone.utc)
        hour = now.hour
        if hour >= _ENCRYPTED_TRAFFIC["off_hours_threshold"] or hour <= _ENCRYPTED_TRAFFIC["early_hours_threshold"]:
            # Off-hours encrypted traffic is more suspicious
            if result["is_anomalous"]:
                result["risk_score"] = min(result["risk_score"] + 0.2, 1.0)
                result["reason"] += " during off-hours"
            else:
                result["is_anomalous"] = True
                result["risk_score"] = 0.4
                result["reason"] = f"Encrypted traffic during off-hours ({hour}:00)"
            result["actions"].append(ResponseAction.NOTIFY_SECURITY)

        # Check destination port for suspicious encrypted services
        dst_port = p.get("dst_port")
        if dst_port and dst_port in _ENCRYPTED_TRAFFIC["suspicious_ports"]:
            # e.g., SSH, RDP, database ports - high risk if unusual
            if result["is_anomalous"]:
                result["risk_score"] = min(result["risk_score"] + 0.1, 1.0)
                result["reason"] += f" on suspicious port {dst_port}"
            else:
                result["is_anomalous"] = True
                result["risk_score"] = 0.3
                result["reason"] = f"Encrypted traffic to suspicious port {dst_port}"

        # Check for unusual outbound ratio (if we had historical baseline, we'd compare)
        # For now, just note if it's outbound to external IP
        dst_ip = p.get("dst_ip")
        if dst_ip and not self._is_private_ip(dst_ip):
            # External destination
            if result["is_anomalous"]:
                result["risk_score"] = min(result["risk_score"] + 0.1, 1.0)
                result["reason"] += " to external destination"
            else:
                result["is_anomalous"] = True
                result["risk_score"] = 0.2
                result["reason"] = f"Encrypted traffic to external IP {dst_ip}"

        return result

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range (simplified)"""
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") or ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31."):
            return True
        return ip == "127.0.0.1" or ip == "::1"

    # ============================================================
    # NEW: Honeypot Detection
    # ============================================================

    def _check_honeypot(self, p: dict) -> dict:
        """
        Check if the destination IP belongs to a honeypot segment.
        Returns dict: is_honeypot, risk_score, reason.
        """
        dst_ip = p.get("dst_ip")
        if not dst_ip:
            return {"is_honeypot": False, "risk_score": 0.0, "reason": "No destination IP"}

        # Simplified IP-in-network check (would use ipaddress module in production)
        for cidr in _HONEYPOT_IPS:
            if self._ip_in_network(dst_ip, cidr):
                return {
                    "is_honeypot": True,
                    "risk_score": 0.9,
                    "reason": f"Access to honeypot network {cidr} from {p.get('src_ip', 'unknown')}"
                }

        return {"is_honeypot": False, "risk_score": 0.0, "reason": "Not a honeypot"}

    def _ip_in_network(self, ip: str, cidr: str) -> bool:
        """
        Simplified check if IP is in CIDR range.
        In production, use ipaddress module.
        """
        # Very crude: just check prefix for common /24 ranges used in demo
        if cidr.endswith("/24"):
            prefix = cidr[:-4]  # remove /24
            return ip.startswith(prefix)
        # For other CIDRs, we'd need proper parsing; fallback
        return False

    # ============================================================
    # Main analyse method
    # ============================================================

    async def analyse(self, event: ThreatEvent) -> AgentFinding:
        await asyncio.sleep(0.05)

        p = event.payload
        actions: list[ResponseAction] = [ResponseAction.LOG, ResponseAction.ALERT_DASHBOARD]
        confidence = 0.55
        severity = event.severity

        # ── Memory threat detection (existing) ──────────────────
        if event.source == "memory_scanner" or p.get("memory_threat_type"):
            memory_threat_type = p.get("memory_threat_type", "")
            process_name = p.get("process_name", "unknown")
            pid = p.get("pid", 0)
            details = p.get("details", "")

            if memory_threat_type == "RANSOMWARE":
                confidence = 0.95
                severity = Severity.CRITICAL
                actions.extend([
                    ResponseAction.ISOLATE_ASSET,
                    ResponseAction.PSEUDO_LOCK,
                    ResponseAction.ESCALATE_SOC,
                    ResponseAction.NOTIFY_SECURITY
                ])
                await self._terminate_process(pid)
                summary = f"🚨 RANSOMWARE DETECTED! Process: {process_name} (PID: {pid}) - {details}"

            elif memory_threat_type in ["ENCODED_POWERSHELL", "SUSPICIOUS_DOWNLOAD"]:
                confidence = 0.85
                severity = Severity.HIGH
                actions.extend([ResponseAction.TERMINATE_PROCESS, ResponseAction.NOTIFY_SECURITY])
                await self._terminate_process(pid)
                summary = f"Malicious process detected: {process_name} (PID: {pid}) - {details}"

            elif memory_threat_type == "SUSPICIOUS_PROCESS":
                confidence = 0.80
                severity = Severity.HIGH
                actions.append(ResponseAction.TERMINATE_PROCESS)
                await self._terminate_process(pid)
                summary = f"Suspicious process: {process_name} (PID: {pid}) - {details}"

            elif memory_threat_type == "HIGH_MEMORY_USAGE":
                confidence = 0.65
                severity = Severity.MEDIUM
                summary = f"High memory usage: {process_name} (PID: {pid}) - {details}"
            else:
                summary = f"Memory threat detected: {process_name} - {details}"

        # ── Network intrusion enrichment ────────────────────────
        elif event.threat_type == ThreatType.NETWORK_INTRUSION:
            sig = p.get("signature", "")
            rate = p.get("packet_rate", 0)

            # ---- NEW: Encrypted traffic analysis ----
            enc_result = self._analyze_encrypted_traffic(p)
            if enc_result["is_anomalous"]:
                confidence = min(confidence + enc_result["risk_score"] * 0.5, 1.0)
                if enc_result["risk_score"] > 0.5:
                    severity = Severity.HIGH
                actions.extend(enc_result["actions"])
                # Add explanation to summary later

            # ---- NEW: Honeypot detection ----
            honeypot_result = self._check_honeypot(p)
            if honeypot_result["is_honeypot"]:
                confidence = min(confidence + 0.4, 1.0)
                severity = Severity.CRITICAL
                actions.extend([
                    ResponseAction.ISOLATE_ASSET,
                    ResponseAction.ESCALATE_SOC,
                    ResponseAction.NOTIFY_SECURITY,
                    ResponseAction.PSEUDO_LOCK
                ])
                # This is a strong signal; we can add a specific action
                if ResponseAction.BLOCK_ACCESS not in actions:
                    actions.append(ResponseAction.BLOCK_ACCESS)

            # ---- Existing signature/rate checks ----
            if sig in _CRITICAL_SIGNATURES:
                confidence = min(confidence + 0.30, 1.0)
                actions.append(ResponseAction.ISOLATE_ASSET)
                actions.append(ResponseAction.PSEUDO_LOCK)

            for threshold, sev in _RATE_THRESHOLDS.items():
                if rate >= threshold:
                    severity = sev
                    confidence = min(confidence + 0.10, 1.0)
                    break

            if severity in (Severity.HIGH, Severity.CRITICAL):
                actions.append(ResponseAction.NOTIFY_SECURITY)

            # Build summary with new findings
            summary_parts = [
                f"Detected {sig or 'unknown'} from {p.get('src_ip', '?')} "
                f"on port {p.get('dst_port', '?')} at {rate} pkt/s."
            ]
            if enc_result["is_anomalous"]:
                summary_parts.append(f"Encrypted traffic anomaly: {enc_result['reason']}")
            if honeypot_result["is_honeypot"]:
                summary_parts.append(f"🚨 HONEYPOT ACCESS: {honeypot_result['reason']}")
            summary = " — ".join(summary_parts)

        # ── Insider threat ──────────────────────────────────────
        elif event.threat_type == ThreatType.INSIDER_THREAT:
            vol = p.get("unusual_data_volume_gb", 0)
            dst = p.get("destination", "unknown")
            time = p.get("time_of_day", "")

            if vol > 10 or dst == "external_usb":
                confidence = min(confidence + 0.25, 1.0)
                actions.extend([ResponseAction.REVOKE_IDENTITY, ResponseAction.ESCALATE_SOC])

            summary = (
                f"User {p.get('user_id', '?')} transferred {vol} GB to {dst} at {time}."
            )

        else:
            summary = f"Anomalous behavior detected from {p.get('src_ip', event.source)}."

        if severity == Severity.CRITICAL:
            actions.append(ResponseAction.ESCALATE_SOC)

        return AgentFinding(
            agent_name=self.name,
            event_id=event.event_id,
            threat_type=event.threat_type,
            severity=severity,
            confidence=round(confidence, 2),
            summary=summary,
            actions=list(dict.fromkeys(actions)),
            metadata={"raw_payload": p},
        )