"""core/orchestrator.py — AiBoO Orchestrator (tri-gate edition with Zero Trust Layer 1 + Layer 2 Detection & Intelligence + Layer 3 Cyber‑Physical Convergence)."""
from __future__ import annotations
import asyncio
import logging
import configparser
import os
import sys
from .event_bus import EventBus
from gates import Gate1Perimeter, Gate2Behavioural, Gate3Adaptive, GateResponseBridge
from gates.gate3_adaptive import current_importance
from gates.device_posture import configure_device_trust
from gates.threat_intel_lookup import configure_threat_intel
from gates.trigate_memory import TriGateMemory, configure_memory
from gates.trigate_patterns import configure_settings
from gates.threat_feeds import FeedManager, parse_feed_list
from gates.compliance_checks import build_report as build_compliance_report
from log_ingestion import WindowsEventIngestor
from core.zero_trust_pdp import ZeroTrustPDP
from core.zero_trust_pep import ZeroTrustPEP

from core.alert_queue import OfflineQueueManager
from core.backend_bridge import DashboardBridge
from core.process_killer import ProcessKiller  # <-- NEW IMPORT
from core.command_channel import CommandChannel
from core.test_event_injector import make_test_event_handler

# Remote actions the dashboard is allowed to trigger on this endpoint
# (matches the "Dispatch Remote Action" dropdown in the dashboard).
REMOTE_ALLOWED_ACTIONS = {
    "terminate_process", "isolate_asset", "block_access", "quarantine_device",
    "force_logout", "revoke_identity", "pseudo_lock",
    # dynamic access control (response/access_control.py)
    "restrict_identity", "lift_restriction", "revoke_session", "step_up_auth",
    "throttle_segment", "remove_throttle",
}

STATUS_REPORT_SECONDS = 300


def _cfg_float(cfg: dict, key: str, default: float) -> float:
    try:
        return float(str(cfg.get(key, "")).strip() or default)
    except (TypeError, ValueError):
        return default


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
        from engines.incident_correlator import IncidentCorrelator

        # ---- Tri-gate pipeline (Trust -> Intent -> Impact) ----
        self.trigate_memory = self._setup_trigate()
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
        # Old correlation engine: it made vague "[CORRELATED] Identity
        # compromise with lateral movement" cards with no user / PC. The new
        # IncidentCorrelator (ATTACK CHAIN) replaces it. legacy_correlation = true
        # turns the old one back on.
        self.correlation = CorrelationEngine(bus)
        self._legacy_correlation = _cfg_bool(self.config, 'legacy_correlation', False)
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
        # pseudo_lock actions open a REAL decoy via the PseudoLockAgent
        self.pseudo_lock_agent = next(
            (a for a in self.agents if isinstance(a, PseudoLockAgent)), None
        )
        self.real_response.pseudo_lock_provider = self.pseudo_lock_agent

        # ---- Zero Trust engines (existing) ----
        self.behavioral_dna = BehavioralDNAEngine(bus)
        self.device_trust = DeviceTrustEngine(bus)
        self.risk_scoring = RiskScoringEngine(bus)
        self.zero_trust_pdp = ZeroTrustPDP(bus)
        self.zero_trust_pep = ZeroTrustPEP(bus)

        # ---- Layer 2 Detection & Intelligence engines ----
        self.ueba = UEBAEngine(bus)
        # Old UEBA / Behavioral DNA learn only from alerts -> their "anomalies"
        # repeat existing cards. Quiet unless legacy_behaviour_alerts = true.
        legacy = _cfg_bool(self.config, 'legacy_behaviour_alerts', False)
        self.ueba.publish_alerts = legacy
        self.behavioral_dna.publish_alerts = legacy
        # Real threat intel: live connections vs blocklist + public feeds
        self.threat_intel = ThreatIntelligenceEngine(
            bus, interval=_cfg_float(self.config, 'intel_scan_seconds', 30),
            enabled=_cfg_bool(self.config, 'intel_connection_scan', True))
        # Incident correlation over TriGate decisions (attack chains)
        self.incident_correlator = IncidentCorrelator(
            bus, window_minutes=_cfg_float(self.config, 'correlation_window_minutes', 60))
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
        # PseudoLock approvals: the backend only asks a person to approve TriGate
        # BLOCK actions when this agent does NOT run them automatically.
        self.dashboard_bridge.auto_response = self.auto_response

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
                local_handlers=self._local_command_handlers(),
                register_info=lambda: {"importance": current_importance()[0], "trigate": 2},
            )

        # ---- Process killer (demo: kills notepad.exe / calc.exe every 3s) ----
        # OFF by default: it silently killed any Notepad/Calculator the user
        # opened (and made remote-terminate testing impossible).
        # Enable with  process_killer = true  in config.ini.
        self.process_killer_enabled = _cfg_bool(self.config, 'process_killer', False)
        self.process_killer = ProcessKiller(interval=3.0)

    def _local_command_handlers(self) -> dict:
        """Dashboard commands handled by agent components directly."""
        handlers = {
            "inject_test_event": make_test_event_handler(self.bus),
            # TriGate: Endpoints page importance dropdown / Gates tab feedback
            "set_importance": self._cmd_set_importance,
            "trigate_feedback": self._cmd_trigate_feedback,
        }
        if self.pseudo_lock_agent is not None:
            # Restore button on the Locks tab -> close the real decoy port
            handlers["restore_pseudo_lock"] = self.pseudo_lock_agent.remote_restore
        return handlers

    def _setup_trigate(self) -> TriGateMemory:
        """Disk memory + settings for the TriGate (all config.ini keys optional):

            importance     = normal      # low / normal / high / critical
            business_hours = 8-20        # working hours, local time
            abuseipdb_key  =             # free key from abuseipdb.com (optional)
            device_trust   = true        # Gate 1 checks this PC's antivirus / firewall / updates
            device_check_minutes = 15
        """
        base = self.config.get('_config_dir')
        if not base:
            base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) \
                else os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
        path = os.path.abspath(os.path.join(base, 'trigate_memory.json'))
        mem = configure_memory(path)
        settings = configure_settings(self.config.get('business_hours'), self.config.get('importance'))
        from engines.behaviour_analytics import configure_behaviour_analytics
        from response.access_control import configure_access_control
        feed_keys = parse_feed_list(self.config.get('threat_feeds'))
        self.threat_feeds = FeedManager(os.path.join(os.path.abspath(base), 'threat_feeds'), feed_keys,
                                        refresh_hours=_cfg_float(self.config, 'threat_feed_hours', 24))
        configure_threat_intel(abuseipdb_key=self.config.get('abuseipdb_key', ''), feeds=self.threat_feeds)
        dev = configure_device_trust(self.config.get('device_trust', 'true'),
                                     self.config.get('device_check_minutes', 15))
        self.behaviour = configure_behaviour_analytics(
            self.config.get('behaviour_analytics', 'true'), self.config.get('behaviour_min_logons', 20),
            self.config.get('behaviour_min_days', 3), memory=mem)
        self.access_control = configure_access_control(
            os.path.abspath(os.path.join(base, 'access_control_state.json')),
            protected_ips=self._backend_ips(), start=False)
        log.info("Intelligence: threat feeds %s, behaviour analytics %s, incident correlation ON",
                 ", ".join(feed_keys) or "OFF",
                 f"ON (learns after {self.behaviour.min_logons} logons / {self.behaviour.min_days} days)"
                 if self.behaviour else "OFF")
        imp, where = current_importance()
        log.info("TriGate: importance %s (%s), working hours %d:00-%d:00, threat intel: blocklist%s, "
                 "device trust %s, memory %s", imp.upper(), where, settings.business_hours[0],
                 settings.business_hours[1], " + AbuseIPDB" if self.config.get('abuseipdb_key') else "",
                 f"ON (every {dev.minutes:g} min)" if dev.enabled else "OFF", path)
        return mem

    def _backend_ips(self) -> list:
        """IPs of the dashboard backend - never throttled (agent would lose its link)."""
        import socket
        from urllib.parse import urlparse
        host = urlparse(self.config.get('remote_url') or '').hostname
        if not host:
            return []
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except OSError:
            return [host]

    def _status_payload(self) -> dict:
        """Live status of the intelligence features for the dashboard."""
        out = {
            "threat_intel": self.threat_intel.status(),
            "behaviour": self.behaviour.stats() if self.behaviour else {"enabled": False},
            "correlation": self.incident_correlator.stats(),
            "access_control": self.access_control.snapshot(),
            "auto_response": self.auto_response,
        }
        return out

    async def _status_loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            try:
                await self.dashboard_bridge.send("agent-status", self._status_payload())
            except Exception as exc:
                log.debug("status report failed: %s", exc)
            await asyncio.sleep(STATUS_REPORT_SECONDS)

    def _on_posture(self, posture) -> None:
        """Posture thread -> build the compliance report and queue it."""
        loop = getattr(self, "_loop", None)
        if loop is None:
            return
        try:
            report = build_compliance_report(posture, self.trigate_memory,
                                             endpoint=self.dashboard_bridge._endpoint_id)
        except Exception as exc:
            log.debug("compliance report failed: %s", exc)
            return
        asyncio.run_coroutine_threadsafe(self.dashboard_bridge.send("compliance", report), loop)
        log.info("Compliance report: score %s/100 (%d pass, %d fail, %d warn)", report["score"],
                 report["counts"]["pass"], report["counts"]["fail"], report["counts"]["warn"])

    async def _cmd_set_importance(self, target: str, params: dict) -> dict:
        """Dashboard Endpoints page: set this PC's importance (saved on disk)."""
        value = (params or {}).get("importance") or target
        try:
            imp = self.trigate_memory.set_importance(value)
        except ValueError as exc:
            raise RuntimeError(str(exc))
        log.warning("TriGate importance of this PC set to %s from the dashboard", imp.upper())
        return {"importance": imp}

    async def _cmd_trigate_feedback(self, target: str, params: dict) -> dict:
        """Gates tab: 'False alarm' / 'Confirmed threat' for a decision."""
        params = params or {}
        kind = str(params.get("feedback") or "").strip().lower()
        try:
            result = self.trigate_memory.add_feedback(
                kind, event_id=str(params.get("event_id") or target or "") or None,
                pattern=params.get("pattern") or None, entity=params.get("entity"))
        except (KeyError, ValueError) as exc:
            raise RuntimeError(str(exc).strip("'\""))
        log.warning("TriGate feedback '%s' for %s - similar events will now score %s",
                    kind, result["key"], "LOWER" if kind == "false_alarm" else "HIGHER")
        return result

    async def _trigate_autosave(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                self.trigate_memory.maybe_save()
            except Exception as exc:
                log.debug("TriGate autosave failed: %s", exc)

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
                    cfg['_config_dir'] = os.path.dirname(os.path.abspath(config_path))
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
        self._autosave_task = asyncio.create_task(self._trigate_autosave())

        # ---- Start core engines (disabled) ----
        if self._legacy_correlation:
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
        self.threat_feeds.start()
        self.threat_intel.start()
        self.incident_correlator.start()
        self.access_control.start()
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
        self._loop = asyncio.get_running_loop()
        self._status_task = asyncio.create_task(self._status_loop())
        from gates.device_posture import get_posture_monitor
        monitor = get_posture_monitor()
        monitor.add_listener(self._on_posture)
        if monitor.get() is not None:        # first check finished before we listened
            self._on_posture(monitor.get())
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
        # Runs as a background task: ingestor.start() loops forever, and
        # awaiting it here meant start() never returned on Windows (so the
        # "AiBoO started" message and clean Ctrl+C shutdown never happened).
        async def _run_ingestor():
            try:
                await self.windows_ingestor.start(tail_only=True)
            except Exception as e:
                log.warning(f"Windows Event Log ingestion failed: {e}")

        self._ingestor_task = asyncio.create_task(_run_ingestor())

        log.info(
            "Platform ready — tri-gate pipeline + %d specialist agents + "
            "Zero Trust engines + Layer 2 engines + Layer 3 CSDE + "
            "offline queue + remote command channel",
            len(self.agents)
        )

    async def shutdown(self) -> None:
        log.info("Shutting down AiBoO...")

        # ---- Stop the agent-status reporter ----
        task = getattr(self, "_status_task", None)
        if task and not task.done():
            task.cancel()

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
        self.threat_feeds.stop()
        self.access_control.stop()
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
        if self._legacy_correlation and hasattr(self.correlation, 'stop'):
            self.correlation.stop()

        # ---- Save TriGate memory (history, known logons, feedback) ----
        task = getattr(self, "_autosave_task", None)
        if task:
            task.cancel()
        self.trigate_memory.save(force=True)
        st = self.trigate_memory.stats()
        log.info("TriGate memory saved: %d events (7 days), %d known users, %d feedback entries -> %s",
                 st["events"], st["users"], st["feedback"], st["path"])