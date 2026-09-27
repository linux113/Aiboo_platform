"""core/orchestrator.py — AiBoO Orchestrator (tri-gate edition with Zero Trust Layer 1 + Layer 2 Detection & Intelligence + Layer 3 Cyber‑Physical Convergence)."""
from __future__ import annotations
import asyncio
import logging
import configparser
import os
import sys
from .event_bus import EventBus
from gates import Gate1Perimeter, Gate2Behavioural, Gate3Adaptive, GateResponseBridge
from log_ingestion import WindowsEventIngestor
from core.zero_trust_pdp import ZeroTrustPDP
from core.zero_trust_pep import ZeroTrustPEP

from core.alert_queue import OfflineQueueManager
from core.backend_bridge import DashboardBridge
from core.process_killer import ProcessKiller  # <-- NEW IMPORT
from core.command_channel import CommandChannel

# Remote actions the dashboard is allowed to trigger on this endpoint
# (matches the "Dispatch Remote Action" dropdown in the dashboard).
REMOTE_ALLOWED_ACTIONS = {
    "terminate_process", "isolate_asset", "block_access", "quarantine_device",
    "force_logout", "revoke_identity", "pseudo_lock",
}


def _cfg_bool(cfg: dict, key: str, default: bool) -> bool:
    val = str(cfg.get(key, "")).strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default

log = logging.getLogger("Orchestrator")


class Orchestrator:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

        # Load configuration from config.ini (if present)
        self.config = self._load_config()

        # Lazy imports to avoid circular dependency (agents -> core -> agents)
        from agents import (
            CyberThreatAgent, IdentityVerificationAgent, SurveillanceAgent,
            PseudoLockAgent, ZeroTrustAgent, PhishingDetectionAgent, MalwareAnalysisAgent,
        )
        from engines import (
            CorrelationEngine, CommandDashboard, AutonomousResponseEngine,
            BehavioralDNAEngine, DeviceTrustEngine, RiskScoringEngine,
            UEBAEngine, ThreatIntelligenceEngine, PhysicalSecurityEngine,
            InsiderThreatEngine, MetaRiskArbiter, AlertSuppressionEngine,
            ConvergedSecurityEngine, ComplianceEngine, AnomalyDetectionEngine,
        )
        from response import RealResponseEngine

        # ---- Tri-gate pipeline ----
        self.gate1 = Gate1Perimeter(bus)
        self.gate2 = Gate2Behavioural(bus)
        self.gate3 = Gate3Adaptive(bus)
        self.bridge = GateResponseBridge(bus)

        # ---- Specialist agents ----
        self.agents = [
            CyberThreatAgent(bus),
            IdentityVerificationAgent(bus),
            SurveillanceAgent(bus),
            PseudoLockAgent(bus),
            ZeroTrustAgent(bus),
            PhishingDetectionAgent(bus),
            MalwareAnalysisAgent(bus),
        ]

        # ---- Core engines (DISABLED: Unicode logging causes cp1252 errors) ----
        self.correlation = CorrelationEngine(bus)
        # self.dashboard = CommandDashboard(bus)          # DISABLED
        # self.response_eng = AutonomousResponseEngine(bus) # DISABLED

        # ---- Real Windows Event Log ingestion ----
        self.windows_ingestor = WindowsEventIngestor(bus)

        # ---- Real response engine (executes actions on THIS PC) ----
        # Always created so remote commands from the dashboard can run.
        # Automatic responses (auto-kill / firewall / account lock on Gate 3
        # BLOCK) stay OFF unless config.ini has  auto_response = true
        self.auto_response = _cfg_bool(self.config, 'auto_response', False)
        self.remote_commands = _cfg_bool(self.config, 'remote_commands', True)
        self.real_response = RealResponseEngine(bus, auto_response=self.auto_response)

        # ---- Zero Trust engines (existing) ----
        self.behavioral_dna = BehavioralDNAEngine(bus)
        self.device_trust = DeviceTrustEngine(bus)
        self.risk_scoring = RiskScoringEngine(bus)
        self.zero_trust_pdp = ZeroTrustPDP(bus)
        self.zero_trust_pep = ZeroTrustPEP(bus)

        # ---- Layer 2 Detection & Intelligence engines ----
        self.ueba = UEBAEngine(bus)
        self.threat_intel = ThreatIntelligenceEngine(bus)
        self.physical_security = PhysicalSecurityEngine(bus)
        self.insider_threat = InsiderThreatEngine(bus)
        self.meta_risk_arbiter = MetaRiskArbiter(bus)
        self.alert_suppression = AlertSuppressionEngine(bus)

        # ---- NEW Layer 3 Cyber‑Physical Convergence ----
        self.converged = ConvergedSecurityEngine(bus)

        # ---- NEW engines ----
        self.compliance = ComplianceEngine(bus)
        self.anomaly_detection = AnomalyDetectionEngine(bus)

        # ---- MERN dashboard bridge ----
        # Backend URL comes from config.ini [AIBOO] remote_url (or NODE_BACKEND env).
        self.dashboard_bridge = DashboardBridge(
            bus,
            backend_url=self.config.get('remote_url'),
            api_key=self.config.get('api_key'),
            endpoint_id=self.config.get('endpoint_name') or None,
        )

        # ---- Offline queue ----
        self.queue_manager = OfflineQueueManager(
            remote_url=self.config.get('remote_url'),
            api_key=self.config.get('api_key')
        )

        # ---- Remote command channel (dashboard -> this PC) ----
        self.command_channel = None
        if self.remote_commands:
            self.command_channel = CommandChannel(
                self.real_response,
                backend_url=self.config.get('remote_url'),
                api_key=self.config.get('api_key'),
                endpoint_id=self.dashboard_bridge._endpoint_id,
                allowed_actions=REMOTE_ALLOWED_ACTIONS,
            )

        # ---- Process killer (demo: kills notepad.exe / calc.exe every 3s) ----
        # OFF by default: it silently killed any Notepad/Calculator the user
        # opened (and made remote-terminate testing impossible).
        # Enable with  process_killer = true  in config.ini.
        self.process_killer_enabled = _cfg_bool(self.config, 'process_killer', False)
        self.process_killer = ProcessKiller(interval=3.0)

    def _load_config(self) -> dict:
        """
        Load [AIBOO] settings from config.ini.

        Search order (first hit wins):
          1. Next to the executable (PyInstaller frozen build)
          2. The agent/ directory (source checkout)
          3. The current working directory
        Falls back to NODE_BACKEND env / localhost if no config.ini is found.
        """
        candidates = []
        if getattr(sys, 'frozen', False):
            candidates.append(os.path.join(os.path.dirname(sys.executable), 'config.ini'))
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.ini'))
        candidates.append(os.path.join(os.getcwd(), 'config.ini'))

        for config_path in candidates:
            if os.path.exists(config_path):
                config = configparser.ConfigParser()
                config.read(config_path)
                if 'AIBOO' in config:
                    cfg = dict(config['AIBOO'])
                    cfg['remote_url'] = (cfg.get('remote_url') or '').strip().rstrip('/') \
                        or os.getenv('NODE_BACKEND', 'http://localhost:4000')
                    log.info("Loaded config from %s (backend=%s)",
                             os.path.abspath(config_path), cfg['remote_url'])
                    return cfg

        log.warning("config.ini not found — falling back to NODE_BACKEND / localhost")
        return {
            'remote_url': os.getenv('NODE_BACKEND', 'http://localhost:4000').rstrip('/'),
            'api_key': os.getenv('AGENT_API_KEY', 'dev-key-change-in-production'),
            'endpoint_name': '',
            'server_ip': '192.168.1.100'
        }

    async def start(self) -> None:
        log.info("Starting AiBoO — tri-gate + Zero Trust + Layer 2 Intelligence + Layer 3 Cyber‑Physical Convergence...")

        # ---- Start tri-gate pipeline ----
        self.gate1.start()
        self.gate2.start()
        self.gate3.start()
        self.bridge.start()

        # ---- Start core engines (disabled) ----
        self.correlation.start()
        # self.dashboard.start()          # DISABLED
        # self.response_eng.start()       # DISABLED
        if self.auto_response:
            self.real_response.start()
            log.warning("Real Response Engine: AUTO-RESPONSE ON (auto_response = true)")
        else:
            log.info("Real Response Engine ready - remote commands only "
                     "(set auto_response = true in config.ini for automatic actions)")

        # ---- Start Zero Trust engines ----
        self.behavioral_dna.start()
        self.device_trust.start()
        self.risk_scoring.start()
        self.zero_trust_pdp.start()
        self.zero_trust_pep.start()

        # ---- Start Layer 2 Detection & Intelligence engines ----
        self.ueba.start()
        self.threat_intel.start()
        self.physical_security.start()
        self.insider_threat.start()
        self.meta_risk_arbiter.start()
        self.alert_suppression.start()

        # ---- Start Layer 3 Cyber‑Physical Convergence ----
        self.converged.start()
        log.info("Converged Security Engine started — monitoring ghost logins, insider patterns, tailgating, ransomware preludes")

        # ---- Start NEW engines ----
        self.compliance.start()
        self.anomaly_detection.start()

        # ---- Start MERN dashboard bridge ----
        self.dashboard_bridge.start()
        log.info("DashboardBridge started – using WebSocket endpoint ws://localhost:8000/ws/alerts")

        # ---- Start offline queue ----
        self.queue_manager.start_retry(
            self.config.get('remote_url'),
            self.config.get('api_key')
        )
        log.info("Offline alert queue and retry worker started")

        # ---- Start remote command channel ----
        if self.command_channel:
            self.command_channel.start()
        else:
            log.info("Remote commands disabled (remote_commands = false in config.ini)")

        # ---- Start process killer (local actions) ----
        if self.process_killer_enabled:
            await self.process_killer.start()
            log.info("Process killer started - notepad.exe/calc.exe will be killed")
        else:
            log.info("Process killer disabled (set process_killer = true to enable)")

        # ---- Register specialist agents ----
        for agent in self.agents:
            agent.register()
            if agent.name == "CyberThreatAgent":
                asyncio.create_task(agent.start_memory_scanning())
                log.info("Memory scanning activated for CyberThreatAgent")

        # ---- Start Windows Event Log ingestion ----
        try:
            await self.windows_ingestor.start(tail_only=True)
            log.info("Windows Event Log ingestion active — monitoring Security, System, Application logs")
        except Exception as e:
            log.warning(f"Windows Event Log ingestion failed: {e}")
            log.warning("Running in demo mode with predefined events")

        log.info(
            "Platform ready — tri-gate pipeline + %d specialist agents + "
            "Zero Trust engines + Layer 2 engines + Layer 3 CSDE + "
            "offline queue + remote command channel",
            len(self.agents)
        )

    async def shutdown(self) -> None:
        log.info("Shutting down AiBoO...")

        # ---- Stop remote command channel ----
        if self.command_channel:
            await self.command_channel.stop()

        # ---- Stop process killer ----
        if self.process_killer_enabled:
            await self.process_killer.stop()

        # ---- Stop offline queue ----
        self.queue_manager.stop_retry()

        # ---- Stop memory scanning ----
        for agent in self.agents:
            if agent.name == "CyberThreatAgent" and hasattr(agent, '_memory_scan_running'):
                agent._memory_scan_running = False
                log.info("Memory scanning stopped for CyberThreatAgent")

        # ---- Stop Windows Event Log ingestion ----
        try:
            await self.windows_ingestor.stop()
            log.info("Windows Event Log ingestion stopped")
        except Exception as e:
            log.debug(f"Error stopping ingestor: {e}")

        # ---- Stop Zero Trust components ----
        self.zero_trust_pep.stop()
        self.zero_trust_pdp.stop()
        self.risk_scoring.stop()
        self.device_trust.stop()
        self.behavioral_dna.stop()

        # ---- Stop Layer 2 engines ----
        self.ueba.stop()
        self.threat_intel.stop()
        self.physical_security.stop()
        self.insider_threat.stop()
        self.meta_risk_arbiter.stop()
        self.alert_suppression.stop()

        # ---- Stop Layer 3 Cyber‑Physical Convergence ----
        await self.converged.stop()
        log.info("Converged Security Engine stopped")

        # ---- Stop NEW engines ----
        self.compliance.stop()
        self.anomaly_detection.stop()

        # ---- Stop MERN dashboard bridge ----
        await self.dashboard_bridge.stop()

        # ---- Stop other engines (disabled) ----
        # self.real_response.stop() if hasattr(self.real_response, 'stop') else None
        # self.response_eng.stop() if hasattr(self.response_eng, 'stop') else None
        self.correlation.stop()

        # ---- Log confirmed threats from Gate 3 ----
        fps = self.gate3.known_entities()
        if fps:
            log.info("Gate 3 fingerprint registry — %d confirmed threats:", len(fps))
            for fp in fps:
                log.info("  [%s] %s entity=%r occurrences=%d",
                         fp.severity.value.upper(), fp.threat_type.value,
                         fp.entity, fp.occurrences)
        else:
            log.info("No confirmed threats detected during this session")