"""core/orchestrator.py — AiBoO Orchestrator (tri-gate edition with Zero Trust Layer 1 + Layer 2 Detection & Intelligence + Layer 3 Cyber‑Physical Convergence)."""
from __future__ import annotations
import asyncio
import logging
import configparser
import os
from .event_bus import EventBus
from gates import Gate1Perimeter, Gate2Behavioural, Gate3Adaptive, GateResponseBridge
from log_ingestion import WindowsEventIngestor
from core.zero_trust_pdp import ZeroTrustPDP
from core.zero_trust_pep import ZeroTrustPEP

from core.alert_queue import OfflineQueueManager
from core.backend_bridge import DashboardBridge
from core.process_killer import ProcessKiller  # <-- NEW IMPORT

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
        # self.real_response = RealResponseEngine(bus)    # DISABLED

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
        self.dashboard_bridge = DashboardBridge(bus, backend_url='https://stuffy-volley-had.ngrok-free.dev')

        # ---- Offline queue ----
        self.queue_manager = OfflineQueueManager(
            remote_url=self.config.get('remote_url'),
            api_key=self.config.get('api_key')
        )

        # ---- Process killer (local actions) ----
        self.process_killer = ProcessKiller(interval=3.0)

    def _load_config(self) -> dict:
        """Load configuration from config.ini in the same directory."""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.ini')
        if os.path.exists(config_path):
            config.read(config_path)
            if 'AIBOO' in config:
                return dict(config['AIBOO'])
        # Fallback defaults
        return {
            'remote_url': 'https://stuffy-volley-had.ngrok-free.dev',
            'api_key': 'dev-key-change-in-production',
            'endpoint_name': 'Unknown_PC',
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
        # self.real_response.start()      # DISABLED

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

        # ---- Start process killer (local actions) ----
        await self.process_killer.start()   # <-- NEW
        log.info("Process killer started – listening for high/critical alerts")

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
            "offline queue + process killer (local actions enabled)",
            len(self.agents)
        )

    async def shutdown(self) -> None:
        log.info("Shutting down AiBoO...")

        # ---- Stop process killer ----
        await self.process_killer.stop()   # <-- NEW

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