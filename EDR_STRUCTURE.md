# AiBoO — EDR Architecture of the Whole Codebase

*How this repository maps onto a classic Endpoint Detection & Response (EDR) pipeline — layer by layer, with the real file paths.*

Verified against branch `arena/01a0e300-aiboo-platform`, commit `51afe1a`.

**Scale:** 19 detection engines · 39 TriGate patterns · 32 Linux detectors · 18 Windows specialist agents/engines · 14 backend route modules · 17 database models · 16 backend services · 17 dashboard modules · 451 automated tests.

---

## 1. The EDR reference model (and where AiBoO implements it)

```
┌──────────────────────────── ENDPOINTS (sensors) ─────────────────────────────┐
│  Windows PC: agent/            │  Linux server: linux-agent/                  │
│   L1 Collectors → L2 Normalize → L3 Local detect → L4 Local respond          │
└───────────────┬──────────────────────────────────────────────┬───────────────┘
                │ socket.io (persistent)          │ HTTPS polling (5 s)
                ▼                                 ▼
┌──────────────────────────── SERVER / BRAIN (backend/) ───────────────────────┐
│  L5 Ingest & auth  →  L6 Store  →  L7 Correlate & score  →  L8 Decide        │
│  (agent.routes.js, agentChannel.js)   (models/)   (services/)   (gates,      │
│                                                                  rules)      │
│                        L9 Actuate (command queue → agent)                     │
│                        L10 Present (frontend/ → dashboard)                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

| # | EDR layer | What it means | Where it lives in this repo |
|---|---|---|---|
| L1 | **Collection / telemetry** | read raw events from the OS | `agent/log_ingestion/`, `agent/core/process_monitor.py`, `agent/core/local_events.py`, Linux collectors inside `linux-agent/aiboo_linux_agent.py` |
| L2 | **Transport & delivery** | get events off the endpoint reliably | `agent/core/backend_bridge.py`, `agent/core/alert_queue.py`, `agent/core/command_channel.py` (socket), Linux REST client in `aiboo_linux_agent.py` |
| L3 | **Normalisation / event model** | one shape for every event | `agent/core/events.py`, Linux `Finding`/`to_api()`, `backend/models/Finding.js` |
| L4 | **Detection** | turn events into findings | `agent/gates/trigate_patterns.py` (39), `agent/log_ingestion/windows_event_parser.py`, Linux 32 detectors, `agent/engines/*` |
| L5 | **Correlation & enrichment** | join events across time/source, add intel | `agent/engines/correlation_engine.py`, `incident_correlator.py`, `agent/gates/threat_intel_lookup.py`, `threat_feeds.py`, `agent/engines/threat_intelligence_engine.py` |
| L6 | **Scoring & prioritisation** | how dangerous is it | `agent/engines/risk_scoring_engine.py`, `meta_risk_arbiter.py`, `ueba_engine.py`, `anomaly_detection_engine.py`, `alert_suppression_engine.py` |
| L7 | **Verdict / policy decision** | allow, watch, block | `agent/gates/gate1_perimeter.py`, `gate2_behavioural.py`, `gate3_adaptive.py`, `gate_response_bridge.py`, `backend/services/responseRules.service.js` |
| L8 | **Response / actuation** | actually change something | `agent/response/real_response_engine.py`, `agent/core/local_action_executor.py`, `agent/core/process_killer.py`, `agent/response/access_control.py`, `linux-agent/aiboo_linux_response.py` |
| L9 | **Approval & workflow** | human in the loop | `backend/models/Approval.js`, `backend/services/pseudolock.service.js`, `backend/services/commandQueue.service.js`, `frontend/src/components/ResponseModule.tsx` |
| L10 | **Console & reporting** | what the operator sees | `frontend/src/components/*` (17), `backend/services/reportData.js`, `reportRender.js`, `kpi.service.js` |
| L11 | **Storage / state** | persistence everywhere | `backend/models/*` (Mongo), backend in-memory stores, agent-side JSON (`linux-agent-state.json`, `*-queue.jsonl`, `actions.jsonl`, `state/throttles.json`, `quarantine/`) |
| L12 | **Ops / lifecycle** | install, update, package, test | `agent/build_agent.bat`, `agent/AiBoO-Agent.spec`, `linux-agent/{install.sh,build_dist.sh,install_service.sh}`, `tests/` on both agents, `backend/tests/` |

---

## 2. Endpoint side — Windows agent (`agent/`)

### 2.1 Collection (L1)

| File | Collects |
|---|---|
| `agent/log_ingestion/windows_ingestor.py` | tails the Windows Event Log |
| `agent/log_ingestion/windows_event_parser.py` | parses event XML → structured event |
| `agent/core/process_monitor.py` | running processes, parent/child, command lines |
| `agent/core/local_events.py` | local OS facts (services, users, posture) |
| `agent/api/ingestion_api.py` | entry point for external feeds into the agent |

**Event IDs collected:** 4624/4625 logons, 4720/4726 account create/delete, 4728/4732 admin group adds, 4697/4698/7045 service and scheduled-task installs, 1102 log cleared, 4719 audit policy change, 4740 lockout, 4656/4663 file access, 5140/5145 share access, 5157 firewall change.

### 2.2 Transport (L2)

| File | Role |
|---|---|
| `agent/core/backend_bridge.py` | the single outbound path: subscribes to findings, heartbeat every 60 s, immediate heartbeat at start |
| `agent/core/alert_queue.py` | durable queue — if the server is unreachable, findings wait and are re-sent (no loss) |
| `agent/core/command_channel.py` | socket.io client on namespace `/agent-channel` with `auth{api_key,endpoint_id,hostname}` — how dashboard commands arrive |

### 2.3 Detection & engines (L4–L6)

**TriGate pattern library — `agent/gates/trigate_patterns.py` (39 patterns)** — the first-match rule table: pattern → severity → intent → MITRE mapping. This is the Windows equivalent of the Linux 32 detectors.

**19 engine modules — `agent/engines/`:**

| Engine | EDR role |
|---|---|
| `correlation_engine.py` | joins events across sources |
| `incident_correlator.py` | builds incidents from related alerts |
| `converged_security_engine.py`, `converged_events.py` | IT + physical convergence |
| `risk_scoring_engine.py` | numeric risk |
| `meta_risk_arbiter.py` | resolves conflicting engine opinions |
| `anomaly_detection_engine.py` | statistical outliers |
| `behaviour_analytics.py`, `ueba_engine.py`, `behavioral_dna_engine.py` | user/entity behaviour baselines |
| `insider_threat_engine.py` | insider scenarios |
| `threat_intelligence_engine.py` | feed matching |
| `device_trust_engine.py` | device posture/trust |
| `physical_security_engine.py` | badge/camera events |
| `compliance_engine.py` | control checks |
| `alert_suppression_engine.py` | de-noise / dedup |
| `autonomous_response.py` | unattended response decisions |
| `command_dashboard.py` | operator command surface |

**Verdict pipeline (L7) — `agent/gates/`:**

| File | Gate | Question it answers |
|---|---|---|
| `gate1_perimeter.py` | Gate 1 — **Trust** | is this device/user/network trustworthy? |
| `gate2_behavioural.py` | Gate 2 — **Intent** | off-hours? repeats? new admin? bad command? |
| `gate3_adaptive.py` | Gate 3 — **Impact** | how important is this asset? (endpoint `importance`) |
| `gate_response_bridge.py` | bridge | converts the verdict into a response request |
| `trigate_memory.py` | memory | repeats in 24 h, escalations over 7 days |
| `threat_feeds.py`, `threat_intel_lookup.py` | intel | blocklist / feed match |
| `device_posture.py`, `compliance_checks.py` | posture | is the machine allowed to be trusted? |

**Risk formula (the heart of scoring):**
```
risk = round(0.3 × (100 − Trust) + 0.4 × Intent + 0.3 × Impact)
≥75 critical · ≥55 high → BLOCK
≥35 medium            → HOLD
else                  → PASS
```

### 2.4 Response (L8)

| File | Action it performs |
|---|---|
| `agent/response/real_response_engine.py` | executes approved actions on this PC (block, isolate, kill, quarantine, throttle, lock, logout…) |
| `agent/core/local_action_executor.py` | the local execution wrapper + audit |
| `agent/core/process_killer.py` | targeted process termination with guards |
| `agent/response/access_control.py` | account lock / unlock / step-up |
| `agent/core/zero_trust_pdp.py` / `zero_trust_pep.py` | policy decision + enforcement points |
| `agent/core/executor.py` | safe command execution (no shell) |

### 2.5 Specialist agents (`agent/agents/`)

`CyberThreatAgent`, `IdentityVerificationAgent`, `SurveillanceAgent`, `PseudoLockAgent`, `ZeroTrustAgent`, `PhishingDetectionAgent`, `MalwareAnalysisAgent` — each subscribes to the event bus and contributes findings/verdicts.

### 2.6 The spine

`agent/core/orchestrator.py` — wires everything: event bus → specialist agents → TriGate gates 1-3 → response bridge → engines. `agent/main.py` is the entry point (`python main.py` or the built `AiBoO-Agent.exe`). `agent/core/event_bus.py` + `agent/core/events.py` are the message contract.

---

## 3. Endpoint side — Linux agent (`linux-agent/`)

| EDR layer | Implementation |
|---|---|
| **L1 Collection** | 26 collector sections inside `aiboo_linux_agent.py`: sshd/auth.log, nginx access+error, MySQL error, systemd journals of named services, `/var/log/audit/audit.log`, process table every 15 s, watched folders every 5 min, SUID scan hourly, posture once/day, `blocklist.txt` |
| **L3 Model** | `Finding` dataclass + `to_api()` → identical JSON shape to the Windows agent (source, hostname, platform, severity, pattern, MITRE, evidence) |
| **L4 Detection** | 32 detectors (identity 10 · persistence 2 · web/network 10 · log-tamper 2 · threat-intel 1 · malware/kernel 5 · posture 3) |
| **L7 Verdict** | the same risk formula; verdicts PASS/HOLD/BLOCK sent as `gate-decision` |
| **L8 Response** | `aiboo_linux_response.py` — 19 actions: `block_access`, `isolate_asset`, `unblock_access`, `throttle_segment` (real iptables hashlimit), `remove_throttle`, `terminate_process`, `quarantine_file`, `restore_file`, `revoke_identity`, `restrict_identity` (auto re-enable), `lift_restriction`, `step_up_auth`, `force_logout`, `pseudo_lock`, `restore_pseudo_lock`, `full_isolation`, `release_isolation`, … |
| **L9 Approval** | polls `GET /api/agent/commands/pending` every 5 s, acks each with the honest result |
| **L11 State** | `linux-agent-state.json` (log offsets, dedup, thresholds), `linux-agent-queue.jsonl` (offline spool), `actions.jsonl` (audit), `state/throttles.json` (auto-expiry), `quarantine/` |
| **Guard rails** | `_ip_guard` (no loopback/link-local/AiBoO-server/hostnames), `_refuse_user` (no root, uid<1000, own account), protected PIDs (1, systemd, sshd, auditd, cron, rsyslogd, self), quarantine restricted to `watch_dirs`+tmp |
| **Privilege model** | `sudoers/aiboo-linux-agent.sudoers` — an explicit allowlist of exact commands; `--capabilities` reports `can_change` truthfully |
| **Ops** | `install.sh`, `configure.sh`, `build_dist.sh` (packaging), `install_service.sh` (systemd --user), `tests/{test_linux_agent,test_response,attack_demo,prove_real}` |

---

## 4. Server side — the brain (`backend/`)

### 4.1 Ingest & trust (L5)

| File | Role |
|---|---|
| `routes/agent.routes.js` | every agent endpoint: `/findings`, `/heartbeat`, `/gate-decision`, `/compliance`, `/agent-status`, `/endpoints`, `/actions`, `/commands/pending`, `/commands/:id/ack`, `/commands/history`, `/agents-online`, approvals/playbooks, threat intel |
| `sockets/agentChannel.js` | socket.io namespace `/agent-channel`; `auth{api_key}` must equal `AGENT_API_KEY`; keeps the live agent registry |
| `middleware/auth.js` | JWT + roles (`admin` / `analyst` / `viewer`) |
| `middleware/error.js` | uniform error shape |
| `services/agentWebSocket.js`, `sockets/index.js` | socket bootstrap |

### 4.2 Storage (L11)

**17 Mongo models — `backend/models/`:** `Alert`, `Approval`, `Asset`, `Camera`, `CameraEvent`, `ComplianceReport`, `Detection`, `Finding`, `IdentityRisk`, `Playbook`, `PlaybookRun`, `ResponseAction`, `ResponseRule`, `RuleEvent`, `Threat`, `User`, `Vulnerability`.

**Plus in-memory stores** in `routes/agent.routes.js` (findings, correlated, gate decisions, pseudo-locks, actions, endpoints, importance, agent status, compliance) shared with the socket layer — deliberate for speed, cleared on restart.

### 4.3 Decision & workflow (L7–L9)

| Service | Responsibility |
|---|---|
| `services/responseRules.service.js` + `models/ResponseRule.js` | the operator's "if this, then that" rules (patterns, min risk, verdicts, PC groups, importance, IP kind, hours, cooldown, max/hour, priority) |
| `services/pseudolock.service.js` | approvals engine: create, expiry, who may approve, `LINUX_LABELS`/`actionLabel` mapping for wording per platform |
| `services/commandQueue.service.js` | the transport for REST agents: queue → takePending → finish → `waitForCommand(timeout)`; powers approvals and playbooks on Linux |
| `models/Playbook.js`, `PlaybookRun.js`, `services/response.service.js` | multi-step playbooks and their runs |
| `services/badge.service.js` | physical access / Freeze Badge integration (`BADGE_WEBHOOK_URL`) |
| `services/ai.service.js`, `agent/llm/*` | narrative/hypothesis text (optional, needs a key) |

### 4.4 Presentation & reporting (L10)

| File | Shows |
|---|---|
| `services/reportData.js`, `reportRender.js`, `kpi.service.js` | report payloads and rendering |
| `controllers/*` (8) | dashboard, threat, alert, response, identity, asset, camera, ai |
| `routes/*` (14) | REST surface of all of the above |

---

## 5. Console — the operator's view (`frontend/src/components/`, 17 modules)

| Module | EDR function |
|---|---|
| `DashboardModule.tsx` | SOC overview + **one-click playbooks** (platform-aware wording) |
| `AlertsModule.tsx` | alert triage list |
| `AgentConsole.tsx` | **live response console**: endpoint picker with platform, action catalogue filtered per OS, send-event, isolation & termination history |
| `EndpointsList.tsx` | inventory: online/offline, platform, hostname, importance (TriGate Impact) |
| `ResponseModule.tsx` | approvals queue + playbook editor (approve/deny, run status) |
| `ResponseRules.tsx` | rule automation editor (the "if/then" engine) |
| `TriGateCard.tsx` | verdict card: Trust / Intent / Impact breakdown per alert |
| `IntelligenceModule.tsx` | threat intel: feeds, blocklists |
| `ExecutiveModule.tsx`, `ReportsModule.tsx` | management reporting |
| `SurveillanceModule.tsx`, `CamTile.tsx` | camera/physical layer |
| `SettingsModule.tsx` | users, roles, system settings |
| `AIPanel.tsx` | optional AI assistant |
| `TopBar.tsx`, `KPI.tsx`, `NotificationPanel.tsx` | shell, counters, toasts |

`App.tsx` is the router/auth shell; `utils/api.ts` is the single API client (base URL configurable — relative for cloud, absolute for dev).

---

## 6. Three complete data-flow traces

### Trace A — a Windows PC is under attack

```
1  Windows Event 4625 ×5 (same source IP)
2  agent/log_ingestion/windows_ingestor.py         → parser → events
3  agent/gates/trigate_patterns.py                 → pattern "failed_logon" (medium)
                                                   → after 5: "brute_force" (high)
4  gate1_perimeter (Trust) + gate2_behavioural (Intent) + gate3_adaptive (Impact)
                                                   → risk 58…82 → BLOCK
5  agent/core/backend_bridge.py                    → POST /api/agent/findings
                                                   → POST /api/agent/gate-decision
6  backend/routes/agent.routes.js                  → store + socket emit
7  backend/services/responseRules.service.js        → matching rule?
                                                   → auto playbook OR approval
8  frontend AlertsModule / TriGateCard             → operator sees it
9  Operator presses Block IP → approval
10 backend/services/commandQueue.service.js → socket cmd → agent
11 agent/response/real_response_engine.py           → firewall rule
12 agent → POST /api/agent/…ack                     → ActionRecord → console history
```

### Trace B — a Linux server is under attack (REST path)

```
1  sshd writes "Failed password" → /var/log/auth.log
2  aiboo_linux_agent.py (auth.log collector, 5 s poll) → detector brute_force
3  same risk formula → verdict BLOCK → POST /api/agent/gate-decision
4  backend creates an Approval (pseudolock.service.js)
5  operator approves in ResponseModule.tsx
6  commandQueue.service.js holds it for endpoint "aiboo-linux-01"
7  agent's poll (GET /api/agent/commands/pending, 5 s) picks it up
8  aiboo_linux_response.py block_access → _ip_guard → iptables -I INPUT -s <ip> -j DROP
9  ack → backend ActionRecord → AgentConsole "Isolation & Termination"
10 actions.jsonl on the server = the local audit trail
```

### Trace C — a response playbook runs across 3 steps

```
1  rule / operator starts a playbook (DashboardModule or ResponseModule)
2  backend/services/response.service.js                → PlaybookRun (step 1)
3  commandQueue / socket → agent executes step 1 → ack → next step
4  PLAYBOOK_ACTION_TIMEOUT_SECONDS (90) per step, results recorded
5  PlaybookRun status → UI shows step-by-step state
```

---

## 7. Complete file inventory (what each top-level item is)

| Path | Purpose | EDR layer |
|---|---|---|
| `agent/` | Windows endpoint agent (source, `.exe` build kit, `dist.zip` installer) | L1–L8 |
| `agent/core/` | event bus, orchestrator, transport, executors, Zero-Trust PEP/PDP | L2, L3, L8 |
| `agent/engines/` | 19 detection/correlation/scoring engines | L4–L6 |
| `agent/gates/` | TriGate (Trust/Intent/Impact), threat intel, posture, 39 patterns | L4, L6, L7 |
| `agent/response/` | real response engine + access control | L8 |
| `agent/agents/` | 7 specialist agents | L4–L6 |
| `agent/log_ingestion/` | Windows Event Log ingestion + parsing | L1 |
| `agent/llm/` | narrative & hypothesis text (optional) | L10 |
| `agent/tests/` | 284 pytest tests | quality |
| `linux-agent/` | Linux endpoint agent (package + kit + tests) | L1–L9 |
| `backend/` | brain: API, sockets, queue, rules, approvals, reports | L5–L11 |
| `backend/models/` | 17 Mongo collections | L11 |
| `backend/services/` | decision, workflow, reporting logic | L6–L10 |
| `backend/routes/` | 14 REST modules (agents, auth, alerts, response…) | L5, L10 |
| `frontend/` | operator console (React + Vite) | L10 |
| `agent/build_agent.bat`, `agent/AiBoO-Agent.spec` | Windows packaging/building | L12 |
| `PILOT_TEST_GUIDE.md`, `TRIGATE_TEST_GUIDE.md`, `CLIENT_SETUP.md`, `PSEUDOLOCK_SPECIFICATION_v1.0.md` | docs: test plans, setup, spec | docs |

---

## 8. Where AiBoO is strong, and where a commercial EDR is stronger

| Capability | AiBoO | Typical commercial EDR |
|---|---|---|
| Log/event detection (Windows Event Log, Linux auth/nginx/auditd) | ✅ broad (39 + 32 detectors) | ✅ |
| Behavioural/UEBA scoring, risk formula, MITRE mapping | ✅ | ✅ |
| Multi-layer verdict gates (Trust/Intent/Impact) | ✅ distinctive | usually rule+ML scoring |
| Real response: block, isolate, kill, quarantine, lock, throttle | ✅ both OSes | ✅ |
| Human approval workflow + playbooks + rules | ✅ | ✅ (SOAR-ish) |
| Kernel-level telemetry (driver, ETW deep, eBPF) | ⚠️ partial (auditd/Event Log only) | ✅ kernel drivers |
| Network capture / full packet inspection | ❌ (reads web logs, not packets) | ✅ often NDR built in |
| File rollback / snapshot-restore (ransomware recovery) | ❌ (quarantine only) | ✅ |
| Cloud console multi-tenant, RBAC at scale | ⚠️ single tenant, two roles + viewer | ✅ |
| TLS everywhere, per-endpoint keys | ⚠️ optional HTTPS; one shared agent key | ✅ mTLS / per-agent certs |
| Data persistence of alerts/actions on the server | ⚠️ partially in memory (Mongo for models) | ✅ full datastore |
| Offline buffering on the endpoint | ✅ queue + JSONL spool | ✅ |

**Practical reading:** AiBoO is a *complete EDR architecture* — every layer exists and is wired end to end — with a deliberately thin bottom (no kernel driver, no packet capture) and a thin top (single tenant, in-memory analytics). The kernel-level gaps are exactly the ones the auditd rules and the Linux `/proc` scan partially cover.

---

## 9. One-screen summary

```
COLLECT        Windows Event Log · Linux logs/auditd/proc/files · posture · intel
                   ↓
NORMALISE      ThreatEvent / AgentFinding / Finding  (one shape, platform tagged)
                   ↓
DETECT         Windows: 39 TriGate patterns + 19 engines
               Linux:   32 detectors
                   ↓
CORRELATE      correlation + incident correlator + UEBA + behavioural DNA + de-noise
                   ↓
SCORE          risk = 0.3(100−Trust) + 0.4·Intent + 0.3·Impact      [TriGate 1-2-3]
                   ↓
DECIDE         PASS / HOLD / BLOCK   →   rules → approval or auto-playbook
                   ↓
RESPOND        Windows: firewall, kill, quarantine, lock, step-up, Zero-Trust PEP
               Linux:   iptables/ufw, hashlimit throttle, kill, quarantine,
                        usermod -L, loginctl, pkill, decoy port
                   ↓
CONFIRM        agent ack → ActionRecord → Agent Console history (+ actions.jsonl)
                   ↓
PRESENT        Dashboard · Alerts · TriGate card · Approvals · Rules · Reports
                   ↓
STORE          MongoDB (17 models) + agent state/queues/quarantine
```
