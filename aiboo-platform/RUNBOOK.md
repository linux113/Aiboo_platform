# AiBoO Platform — Complete Runbook
### Run Backend + Frontend + Agent · Receive alerts from other systems · Simulate attacks

---

## 0. Architecture & Ports (what talks to what)

```
[Other PCs / systems]──POST /events──►┌──────────────┐   findings/locks/gates    ┌─────────────┐   Socket.io   ┌──────────┐
[Windows Event Logs]                  │ AGENT :8001  │ ───SQLite queue, retry──► │ BACKEND:4000│ ────────────► │FRONTEND  │
[curl attack sims    ]                │ tri-gate +   │      (X-API-Key)          │  Express +  │               │ :3000    │
                                      │ 7 agents +   │                           │  Mongo +    │               │ React UI │
[Cameras RTSP/webcam]──► CV :5050 ───►│ 15 engines   │                           │  Socket.io  │               └──────────┘
                                      └──────────────┘                           └─────────────┘
```

| Service | Port | Tech | Started by |
|---------|------|------|-----------|
| Agent | **8001** | Python FastAPI + orchestrator | `python main.py` |
| Backend | **4000** | Node Express + MongoDB + Socket.io | `node server.js` |
| Frontend | **3000** | React + Vite | `npm run dev` |
| CV Service (optional) | **5050** | Flask + YOLOv8 | `python app.py` |
| MongoDB | **27017** | Database | `mongod` / service |

---

## 1. Prerequisites (one time)

- **Node.js 18+** — `node -v`
- **Python 3.10+** — `python --version`
- **MongoDB** — local service or a free MongoDB Atlas cluster
- Windows agents/plugins additionally need: PowerShell 5.1 (built into Win10/11)

---

## 2. Start MongoDB

```bash
# Windows (if installed as service)
net start MongoDB

# Linux
sudo systemctl start mongod

# Or via Docker
docker run -d -p 27017:27017 --name aiboo-mongo mongo:7
```

> **No MongoDB?** Create a free cluster at mongodb.com/cloud/atlas and use its connection string as `MONGO_URI` below.

---

## 3. Backend (port 4000)

```bash
cd aiboo-platform/backend
npm install
```

**Create `.env`** (copy from `.env.example`), minimum required:

```ini
PORT=4000
MONGO_URI=mongodb://localhost:27017/aiboo
JWT_SECRET=change-this-to-a-long-random-string
AGENT_API_KEY=dev-key-change-in-production     # agents/plugins authenticate with this
NODE_ENV=development
CORS_ORIGINS=http://localhost:3000
# Optional — AI chat (JARVIS). Key starting with gsk_ uses Groq, sk- uses OpenAI:
OPENAI_KEY=
```

**Create login users** (one time):

```bash
node seed.js
# → admin@example.com / admin123  (admin)
# → analyst@example.com / analyst123 (analyst)
```

**Start:**

```bash
npm start          # or: node server.js
```

**Verify:** open `http://localhost:4000/health` → `{"status":"ok",...}`

---

## 4. Agent (port 8001) — the detection engine

```bash
cd aiboo-platform/agent
pip install -r requirements.txt
```

**Create `config.ini`** in the `agent/` folder (auto-created on first run, but set it manually for correctness):

```ini
[AIBOO]
remote_url = http://localhost:4000        ; URL of YOUR backend (step 3)
api_key = dev-key-change-in-production    ; MUST match backend AGENT_API_KEY
endpoint_name = My-Laptop                 ; unique name shown on dashboard
server_ip = 192.168.1.100
log_level = INFO
; Optional hardening:
; process_killer_enabled = true           ; OFF by default (safe)
; kill_list = malware.exe, hacktool.exe   ; only these processes get killed
```

**Optional environment variables:**

| Variable | Effect |
|----------|--------|
| `ANTHROPIC_API_KEY=sk-ant-...` | Enables real Claude advice/narratives (offline rules used otherwise) |
| `AIBOO_AUTO_ISOLATE=true` | Auto-execute containment on critical findings (≥85% conf) |
| `AIBOO_ALLOW_LOCAL_ACTIONS=true` | Allow real firewall isolation commands |
| `API_PORT=8001` | API port (default 8001 — keep it) |

**Start:**

```bash
python main.py        # FULL pipeline: tri-gate + 7 agents + 15 engines + API
```

- On **Windows**: also tails real Security/System/Application event logs automatically.
- On **Linux/macOS**: runs everything except Windows-log tailing (events arrive via the API instead — see §6).

**Verify:**

```bash
curl http://localhost:8001/health
# → {"status":"healthy","service":"AiBoO Ingestion & Zero Trust API",...}
```

Expected startup log: `Platform ready — tri-gate pipeline + 7 specialist agents + ...`

---

## 5. Frontend (port 3000) + CV Service (optional)

**Frontend:**

```bash
cd aiboo-platform/frontend
npm install
```

Create `.env`:

```ini
VITE_API_URL=http://localhost:4000/api
VITE_SOCKET_URL=http://localhost:4000
VITE_CV_URL=http://localhost:5050
VITE_AGENT_URL=http://localhost:8001
VITE_AGENT_API_KEY=dev-key-change-in-production
```

```bash
npm run dev
```

Open **http://localhost:3000** → login `admin@example.com` / `admin123`.
✅ Top bar should show backend green; Agent Console shows your endpoint as a live source.

**CV Service** (camera AI — optional):

```bash
cd aiboo-platform/cv-service
pip install -r requirements.txt
python app.py          # first run downloads yolov8n.pt
```

---

## 5b. One-click alternatives

- **Windows (bare metal):** just run **`start-all.bat`** — it now auto-installs missing npm/pip dependencies, creates `agent\config.ini` for you (endpoint = your PC name, backend = localhost:4000), waits for first-run model downloads, prints the last log lines of any service that fails to start, and skips services already running. `close-all.bat` stops everything (it also kills by port, so nothing is left behind). `setup.bat` is optional nowadays.
- **Docker:** `cp backend/.env.example backend/.env && cp agent/.env.example agent/.env`, edit both, then `docker compose up --build` (Mongo + backend + frontend + agent + cv-service). The agent container runs the **full pipeline** since the latest fix.

---

## 6. Getting alerts from OTHER systems

Every external system sends events to the agent's API:

```
POST http://<AGENT-PC-IP>:8001/events
Headers:  Content-Type: application/json
          X-API-Key: dev-key-change-in-production        (or Authorization: Bearer <same key>)
Body:     { timestamp, source, event_type, message, severity, payload{} }
```

### Option A — Another Windows PC (official plugin, scheduled task)

On the remote PC:
1. Copy the whole `plugin/` folder over.
2. Edit `plugin/config.txt` — line 1 = your agent PC's IP, line 2 = the API key:
   ```
   192.168.1.100
   dev-key-change-in-production
   ```
3. Right-click `install.bat` → **Run as Administrator** (creates scheduled task "AiBoO Security Plugin", forwards Security event log every few minutes, with offline retry queue).

On the agent PC (once): run `open-firewall.bat` as Administrator so port 8001 accepts LAN traffic.

### Option B — Another Windows PC (simple script, no install)

Copy `remote-log-sender.ps1` to the PC and run:

```powershell
powershell -ExecutionPolicy Bypass -File remote-log-sender.ps1 -ServerUrl "http://192.168.1.100:8001" -Interval 15
```

### Option C — Any system (Linux servers, scripts, SIEM forwarders, IoT)

```bash
curl -X POST http://<AGENT-IP>:8001/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-in-production" \
  -d '{
    "timestamp": "2026-09-12T13:00:00Z",
    "source": "web-server-01",
    "event_type": "network_intrusion",
    "message": "Suspicious outbound traffic",
    "severity": "high",
    "payload": { "src_ip": "10.0.0.5", "dst_port": 443, "signature": "UNUSUAL_OUTBOUND" }
  }'
```

Valid `event_type` values: `network_intrusion`, `identity_mismatch`, `physical_intrusion`, `insider_threat`, `anomalous_behavior`, `memory_threat`, `failed_logon`, `logon_success`, `privilege_use`, `process_create`, `access_request`.
Severity: `low | medium | high | critical`.

### Where alerts flow after that

```
remote system → agent (:8001) → tri-gate + agents → suggestion/finding
              → SQLite queue → backend POST /api/agent/findings (+gates, locks, response-log)
              → Socket.io → dashboard updates LIVE (notifications + Agent Console tabs)
```

If the backend is down, alerts sit in `agent/alerts_queue.db` and auto-retry every 30s (up to 5 attempts) — zero alert loss.

### Backend on a different machine / cloud

If the agent runs on a different PC than the backend, set in the agent's `config.ini`:
- `remote_url = http://<BACKEND-IP>:4000` (LAN), or a public tunnel (below).

### ☁️ Public backend over ngrok (for remote endpoints over the internet)

On the **backend machine**:

```bash
ngrok http 4000
# example output:
#   Forwarding  https://d450-....ngrok-free.app -> http://localhost:4000
```

Then on every **REMOTE** machine that runs a full AiBoO agent, set in `agent/config.ini`:

```ini
[AIBOO]
remote_url = https://d450-....ngrok-free.app     ; your ngrok URL, no trailing slash
api_key = dev-key-change-in-production           ; must match backend AGENT_API_KEY
endpoint_name = Remote-Office-PC                 ; unique per machine
```

Notes that matter:
- The agent already sends the `ngrok-skip-browser-warning` header, so free-tier ngrok cannot swallow alerts.
- ngrok **free URLs change on every restart** of ngrok → re-edit `config.ini` each time, or reserve a free **static domain** at dashboard.ngrok.com → *Domains*, then run `ngrok http 4000 --domain=your-static.ngrok-free.app`.
- The PowerShell **plugins** (`plugin/`, `remote-log-sender.ps1`) talk to the AGENT on port **8001**, not the backend — use the agent PC's LAN IP for those. If the agent is also behind NAT, run a second tunnel (`ngrok http 8001`) and point `-ServerUrl` at it.
- Opening the **dashboard** itself via ngrok needs its own tunnel + CORS: add the dashboard URL to backend `CORS_ORIGINS` and set the frontend's `VITE_API_URL`/`VITE_SOCKET_URL` to the same public URL.
- The backend already has `trust proxy` enabled, so HTTPS client IPs are logged correctly behind the tunnel.

---

## 7. Attack simulation commands (test alerts end-to-end)

### From the UI
**Agent Console → Send Event tab** → fill the form → **Send Test Event** → watch Findings/Gates/Isolation tabs fill in real time.

### From the command line — copy-paste attack pack

```bash
KEY="X-API-Key: dev-key-change-in-production"
URL="http://localhost:8001/events"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# 1) SSH BRUTE FORCE  → Gate1 HOLD → CyberThreatAgent critical finding → Isolation suggestion
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"attack-sim\",\"event_type\":\"network_intrusion\",
  \"message\":\"SSH brute force in progress\",\"severity\":\"critical\",
  \"payload\":{\"src_ip\":\"10.0.0.45\",\"dst_port\":22,\"signature\":\"SSH_BRUTE_FORCE\",\"packet_rate\":12500}}"

# 2) FAILED LOGON BRUTE FORCE (Windows-style 4625) → IdentityAgent + ZeroTrustAgent
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"dc-01\",\"event_type\":\"failed_logon\",
  \"message\":\"4625: repeated failed logons\",\"severity\":\"high\",
  \"payload\":{\"user_id\":\"administrator\",\"src_ip\":\"10.0.0.9\",\"failure_reason\":\"wrong password\"}}"

# 3) IMPOSSIBLE TRAVEL / IDENTITY MISMATCH → IdentityAgent geo-velocity
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"vpn-gw\",\"event_type\":\"identity_mismatch\",
  \"message\":\"Login from two countries within minutes\",\"severity\":\"high\",
  \"payload\":{\"user_id\":\"alice\",\"claimed_location\":\"Mumbai, IN\",\"detected_location\":\"Berlin, DE\"}}"

# 4) PHYSICAL BREACH (server room, no badge/face) → Gate1 ESCALATE → Gate3 BLOCK → AUTO pseudo-lock
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"cctv-07\",\"event_type\":\"physical_intrusion\",
  \"message\":\"Unauthorized person in restricted zone\",\"severity\":\"critical\",
  \"payload\":{\"zone\":\"server_room\",\"face_match\":false,\"badge_scan\":false,\"motion_anomaly_score\":0.95}}"

# 5) INSIDER DATA THEFT → InsiderThreatEngine + Converged engine
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"dlp\",\"event_type\":\"insider_threat\",
  \"message\":\"Bulk copy to external USB off-hours\",\"severity\":\"critical\",
  \"payload\":{\"user_id\":\"contractor_17\",\"volume_gb\":15.2,\"destination\":\"external_usb\"}}"

# 6) PHISHING URL → PhishingDetectionAgent
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"mail-gw\",\"event_type\":\"anomalous_behavior\",
  \"message\":\"User clicked suspected phishing link\",\"severity\":\"high\",
  \"payload\":{\"user_id\":\"bob\",\"urls\":[\"http://paypa1-secure.tk/verify?user=bob\"]}}"

# 7) MALWARE HASH → MalwareAnalysisAgent
curl -s -X POST $URL -H "Content-Type: application/json" -H "$KEY" -d "{
  \"timestamp\":\"$TS\",\"source\":\"edr-lite\",\"event_type\":\"memory_threat\",
  \"message\":\"Known malware hash on disk\",\"severity\":\"critical\",
  \"payload\":{\"user_id\":\"bob\",\"file_hashes\":{\"sha256\":\"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\"}}}"
```

### What you should see after each one

| Where | What appears |
|-------|--------------|
| Frontend notifications (bell) | Live toast for high/critical findings |
| Agent Console → **Findings** | The agent findings with severity + confidence |
| Agent Console → **Gates** | Gate 1/2/3 decisions with verdicts (hold/pass/block/escalate) |
| Agent Console → **Locks** | Pseudo-locks with decoy endpoints (attack #4 triggers one) |
| Agent Console → **Isolation** | AI suggestion cards → **⚡ Take Action** or **Dismiss** |
| Agent Console → **AI Insights** | Threat hypotheses (attacker's next move) + incident narratives |
| `GET :8001/llm/insights` | Narrative report + attacker next-move hypothesis |

### Inspect results via API

```bash
K="X-API-Key: dev-key-change-in-production"
curl -s -H "$K" http://localhost:8001/isolation/suggestions | python3 -m json.tool
curl -s -H "$K" http://localhost:8001/isolation/stats
curl -s -H "$K" http://localhost:8001/llm/insights
curl -s http://localhost:4000/api/agent/findings            # what the dashboard sees
curl -s http://localhost:4000/api/agent/sources             # live endpoints
```

---

## 7b. Testing from a REMOTE PC — step-by-step (detailed)

### Scenario A — Remote Windows PC ships its logs to your agent (LAN) — RECOMMENDED FIRST TEST

**On the MAIN PC** (running the stack):

1. Find your LAN IP:
   ```bat
   ipconfig   :: look for "IPv4 Address" e.g. 192.168.1.100
   ```
2. Open the firewall for the agent API (run as Administrator):
   ```bat
   open-firewall.bat
   ```
3. Confirm the agent is listening on all interfaces:
   ```bat
   netstat -an | findstr :8001    :: must show 0.0.0.0:8001 LISTENING
   ```
4. Note your key: `dev-key-change-in-production` (or your custom `AGENT_API_KEY`).

**On the REMOTE PC:**

5. Copy the `plugin/` folder (or just `remote-log-sender.ps1`) over — USB/network share.
6. Quick connectivity check first:
   ```powershell
   Test-NetConnection 192.168.1.100 -Port 8001    :: TcpTestSucceeded : True
   ```
   - If False: firewall on main PC (step 2), or you're on different subnets/VLANs.
7. **Send one manual test event** (fastest way to prove the path — no install needed):
   ```powershell
   $body = @{
     timestamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
     source     = $env:COMPUTERNAME
     event_type = "failed_logon"
     message    = "manual connectivity test from remote PC"
     severity   = "high"
     payload    = @{ user_id = "test"; src_ip = "10.0.0.99" }
   } | ConvertTo-Json
   Invoke-RestMethod -Uri "http://192.168.1.100:8001/events" -Method Post `
     -ContentType "application/json" `
     -Headers @{ "X-API-Key" = "dev-key-change-in-production" } `
     -Body $body
   ```
   Expected: `status=accepted, event_id=<8 chars>`.
8. **Install the continuous forwarder** — Option 1 (scheduled task, survives reboot):
   - Edit `plugin\config.txt` → line 1: `192.168.1.100`, line 2: `dev-key-change-in-production`
   - Right-click `install.bat` → **Run as Administrator**
   - It creates scheduled task "AiBoO Security Plugin" (forwards Security events every few min, offline retry queue included).
   - Uninstall anytime: `uninstall.bat` (admin).
9. **Option 2** (lightweight console script):
   ```powershell
   powershell -ExecutionPolicy Bypass -File remote-log-sender.ps1 -ServerUrl "http://192.168.1.100:8001" -Interval 15
   ```
   Note: this script sends `Authorization: Bearer` — pass the key via `-AuthToken dev-key-change-in-production` if you changed it from the default.
10. **Verify on the MAIN PC:**
    ```bash
    curl http://localhost:4000/api/agent/sources        → ["REMOTE-PC-NAME", ...]
    curl "http://localhost:4000/api/agent/findings?limit=5"
    ```
    Dashboard → Agent Console: your remote PC appears as a live endpoint; real 4625/4624 Security events arrive as findings within minutes.
    Agent log (`logs\agent.log`): `Received event from REMOTE-PC-NAME: ...`

### Scenario B — Remote PC runs its OWN full agent → pushes to your backend over ngrok

Use this when the remote PC is off-LAN (home/branch office) and you want full local detection there.

1. **Main PC:** start the tunnel → `ngrok http 4000` → copy the `https://xxxx.ngrok-free.app` URL.
2. **Remote PC:** install Python 3.10+, copy the whole `agent/` folder, then:
   ```bat
   pip install -r requirements.txt
   ```
3. Create `agent\config.ini` on the remote PC:
   ```ini
   [AIBOO]
   remote_url = https://xxxx.ngrok-free.app
   api_key = dev-key-change-in-production
   endpoint_name = Branch-Office-PC
   server_ip = 127.0.0.1
   log_level = INFO
   ```
4. Start it: `python main.py` → expect `Platform ready — tri-gate pipeline + 7 specialist agents...`
5. **Verify delivery:** on the remote PC generate a critical event:
   ```powershell
   # same Invoke-RestMethod as step 7 above, but URL = http://localhost:8001
   ```
   Then on the main PC: `curl http://localhost:4000/api/agent/sources` → includes `Branch-Office-PC`.
6. **Test the offline queue:** stop ngrok (Ctrl+C), send 2–3 events on the remote PC (they'll queue in SQLite `alerts_queue.db`), restart ngrok with the SAME URL (or update config.ini if URL changed), wait ≤30s → the queued alerts flush automatically.
7. Real detections also flow: log in/out on the remote PC (Windows Security events → 4624/4625) and watch findings appear on your dashboard.

### Scenario C — Remote Linux server (SSH box, no install of plugin)

```bash
curl -X POST http://192.168.1.100:8001/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-key-change-in-production" \
  -d '{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":"prod-server-01","event_type":"anomalous_behavior","message":"cron job ran outside schedule","severity":"medium","payload":{"user_id":"root","process":"cron"}}'
```
Wrap this in a cron/systemd timer or shell into your app's audit log to forward anything.

### Remote testing checklist (what to look for on the dashboard)

| Step | Action on remote PC | Expected on dashboard (within ~10s) |
|------|--------------------|--------------------------------------|
| 1 | Manual test event (high) | 🔔 notification + finding in Agent Console |
| 2 | Critical event (`physical_intrusion` server_room payload) | Gates tab: ESCALATE→BLOCK, Locks tab: new pseudo-lock, Isolation tab: AI suggestion |
| 3 | Click **⚡ Take Action** on the suggestion | status → EXECUTED; `GET /api/agent/response-log` shows the mirrored action |
| 4 | Kill the network path, send events, restore it | alerts flushed from the SQLite queue automatically |
| 5 | Stop the plugin task (`uninstall.bat`) | endpoint goes grey/offline in EndpointsList after ~2 min |

## 8. Troubleshooting

| Symptom | Cause → Fix |
|---------|-------------|
| Backend exits: `DB connection error` | MongoDB not running → start it (§2) or fix `MONGO_URI` |
| Login 401 on dashboard | Users not seeded → run `node seed.js` in backend |
| Agent log: retry worker `Connection refused` | Backend not reachable → check `remote_url` in `config.ini` and that backend is up |
| Dashboard shows no findings but agent logs them | `api_key` in `config.ini` ≠ `AGENT_API_KEY` in backend `.env` |
| Remote PC plugin events not arriving | Wrong IP/key in `config.txt`, firewall blocking 8001 (run `open-firewall.bat`), or agent started on port 8000 (old build) |
| Frontend "Send Event" fails | Agent not running on 8001, or wrong `VITE_AGENT_API_KEY` |
| `Windows Event Log ingestion failed` on Linux | Expected — Linux has no Windows logs; use API events (§6C) |
| AI advice says `offline rules` | No `ANTHROPIC_API_KEY` set — set it to enable Claude |
| Isolation shows `simulated` note | Real firewall isolation disabled → `AIBOO_ALLOW_LOCAL_ACTIONS=true` |

---

## 9. Security notes for production

- Change `AGENT_API_KEY`, `JWT_SECRET`, and remove default users from `seed.js`.
- Keep `AIBOO_ALLOW_LOCAL_ACTIONS` and `AIBOO_AUTO_ISOLATE` **off** until you trust the pipeline; the Isolation tab's manual **Take Action** is the safe path.
- ProcessKiller is OFF by default — enable only with an explicit `kill_list`.
- Put HTTPS in front of the backend (ngrok/Caddy/nginx) before exposing beyond LAN.
