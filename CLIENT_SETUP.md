# AiBoO Platform — Client Setup Guide

## Prerequisites

| Software | Version | Download |
|----------|---------|----------|
| Node.js | 18+ | https://nodejs.org |
| Python | 3.10+ | https://python.org |
| MongoDB | 7+ | https://mongodb.com/try/download/community |
| Git | Latest | https://git-scm.com |

---

## Step 1 — Get the Code

```bash
git clone <your-repo-url> aiboo-platform
cd aiboo-platform
```

Expected output:
```
Cloning into 'aiboo-platform'...
Receiving objects: 100%, done.
Resolving deltas: 100%, done.
```

---

## Step 2 — Start MongoDB

Open **Task Manager → Services → MongoDB** or run:

```bash
net start MongoDB
```

Expected output:
```
The MongoDB service is starting...
The MongoDB service was started successfully.
```

Verify:
```bash
mongosh --quiet --eval "db.runCommand('ping').ok"
# Output: 1
```

---

## Step 3 — Backend Setup

```bash
cd backend
npm install
```

Expected output:
```
added 452 packages in 12s
```

Create `.env` (already exists in repo — verify contents):
```
PORT=4000
MONGO_URI=mongodb://localhost:27017/aiboo
JWT_SECRET=ab7f3e91c8d24b5a6f0e927c1d3a8b4e5f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e
NODE_ENV=development
```

Seed the database:
```bash
npm run seed
```

Expected output:
```
✅ MongoDB Connected
🧹 Dropping database...
✅ Users: admin@example.com/admin123 · analyst@example.com/analyst123
✅ Users only — no demo cameras, detections, or threats

🎉 SEEDING COMPLETE
   admin@example.com  / admin123
   analyst@example.com / analyst123
```

Start backend:
```bash
npm start
```

Expected output:
```
[INFO] MongoDB connected: mongodb://localhost:27017/aiboo
[INFO] Server running on port 4000
[INFO] Demo agent data seeded
```

Verify:
```bash
curl http://localhost:4000/api/auth/login -Method POST -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}'
```
```json
{"token":"eyJhbGciOiJIUzI1NiIs...", "user":{...}}
```

---

## Step 4 — Frontend Setup

Open a **new terminal**:

```bash
cd frontend
npm install
```

Expected output:
```
added 1420 packages in 45s
```

Create `.env` (copy from `src/.env` if it exists, or create manually):
```
VITE_API_URL=http://localhost:4000/api
VITE_SOCKET_URL=http://localhost:4000
VITE_CV_URL=http://localhost:5050
VITE_AGENT_URL=http://localhost:8001
```

Start dev server:
```bash
npm run dev
```

Expected output:
```

  VITE v7.2.4  ready in 788 ms

  ➜  Local:   http://localhost:3000/
  ➜  Network: http://192.168.x.x:3000/
```

Open `http://localhost:3000` in browser → Login screen appears.

---

## Step 5 — CV Service Setup

Open a **new terminal**:

```bash
cd cv-service
pip install --prefer-binary -r requirements.txt
```

> If you see numpy build errors, run: `pip install --prefer-binary numpy ultralytics opencv-python-headless flask flask-cors requests deep-sort-realtime Pillow`

Expected output:
```
Successfully installed flask-3.x.x opencv-python-headless-4.x.x ultralytics-8.x.x ...
```

> **Note:** First run downloads `yolov8n.pt` (~6MB) automatically.

Start CV service:
```bash
python app.py
```

Expected output:
```
2026-07-18 20:17:49 [INFO] opencv: YOLOv8 loaded from yolov8n.pt
2026-07-18 20:17:50 [INFO] opencv: DeepSORT loaded
2026-07-18 20:17:50 [INFO] opencv: ==================================================
2026-07-18 20:17:50 [INFO] opencv: AiBoO CV Service starting on 127.0.0.1:5050
2026-07-18 20:17:50 [INFO] opencv:   YOLOv8:    enabled
2026-07-18 20:17:50 [INFO] opencv:   DeepSORT:  enabled
2026-07-18 20:17:50 [INFO] opencv:   Detection: full-spectrum (objects/animals/fire/smoke/faces/motion/falls/tamper/tripwire/traffic)
2026-07-18 20:17:50 [INFO] opencv:   Auth:      using default token (CHANGE IN PRODUCTION)
2026-07-18 20:17:50 [INFO] opencv:   CORS:      http://localhost:3000
2026-07-18 20:17:50 [INFO] opencv: ==================================================
 * Running on http://127.0.0.1:5050
```

---

## Step 6 — Agent Service Setup

Open a **new terminal**:

```bash
cd agent
pip install -r requirements.txt
```

Expected output:
```
Successfully installed fastapi-0.x.x uvicorn-0.x.x pydantic-2.x.x ...
```

Start agent:
```bash
python main.py
```

Expected output:
```
2026-07-18 20:10:00 [INFO] Agent service starting on port 8001
2026-07-18 20:10:00 [INFO] Agent modules loaded: CyberThreatAgent, SurveillanceAgent, ...
INFO:     Uvicorn running on http://0.0.0.0:8001
```

---

## Step 7 — Verify Everything is Connected

From a **new terminal**, run:

```bash
# Login to get token
$token = (Invoke-RestMethod -Uri "http://localhost:4000/api/auth/login" -Method Post -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}').token
$authH = @{Authorization="Bearer $token"}

# 1. Backend health
Invoke-RestMethod -Uri "http://localhost:4000/api/auth/me" -Headers $authH
```
```json
{"_id":"...","name":"Admin","email":"admin@example.com","role":"admin"}
```

```bash
# 2. Agent health
Invoke-RestMethod -Uri "http://localhost:8001/health"
```
```json
{"status":"healthy","service":"agent"}
```

```bash
# 3. CV health
Invoke-RestMethod -Uri "http://localhost:5050/health"
```
```json
{"status":"ok","yolo":true,"deepsort":true,"cameras":0}
```

```bash
# 4. Demo data loaded
Invoke-RestMethod -Uri "http://localhost:4000/api/agent/findings" -Headers $authH
```
```json
[
  {"id":"f001","agent_name":"CyberThreatAgent","threat_type":"network_intrusion","severity":"critical","summary":"SSH_BRUTE_FORCE detected from 10.0.0.45..."},
  {"id":"f002","agent_name":"SurveillanceAgent","threat_type":"physical_intrusion","severity":"high","summary":"Unauthorized access detected in server_room zone."},
  ...
]
```

---

## Step 8 — Deploy Plugin on Client Machines (Windows Only)

The plugin forwards Windows Security event logs from client PCs to the AiBoO dashboard via the Agent service (port 8001).

### Files (in `plugin/` folder)

| File | Purpose |
|------|---------|
| `install.bat` | Install as a scheduled task (run as **Administrator**) |
| `uninstall.bat` | Remove the scheduled task |
| `agent.ps1` | Collects and forwards Security events to the dashboard |
| `config.txt` | Stores the dashboard server IP (auto-created by install) |

### What events are captured

| Event ID | Type | Severity |
|----------|------|----------|
| 4625 | Failed logon | High |
| 4624 | Successful logon | Low |
| 4672 | Privilege use | Medium |
| 4648 | Explicit credential use | Medium |
| 4688 | Process created | Low |
| 5156 | Connection allowed | Low |
| 5157 | Connection denied | Medium |
| 5140 | Share accessed | Medium |
| 5145 | Share access checked | Medium |

### Installation

On the **client PC** (not the dashboard server):

```cmd
# Copy the plugin folder to the client PC
# Right-click install.bat → Run as Administrator

============================================
   AiBoO Security Log Plugin
   Installer for remote log forwarding
============================================

Enter the IP of the PC running the AiBoO dashboard.
Dashboard IP: 192.168.1.100
```

The installer will:
1. Test connection to `http://<dashboard-ip>:8001/health`
2. Save the IP to `config.txt`
3. Create a scheduled task running every 60 seconds as SYSTEM (hidden)
4. Start forwarding events immediately

Expected output:
```
[OK] Server reachable on port 8001
[OK] Config saved: 192.168.1.100
[OK] Plugin installed as background task.
[OK] Runs every 60 seconds (hidden, no window).
[OK] Forwards: failed logons, logons, admin use, processes, connections

============================================
   Installation complete!
============================================

The plugin is now running in the background.
Logs from this PC will appear in your
AiBoO dashboard within 1-2 minutes.
```

### Verification on Dashboard

1. Open `http://localhost:3000` → Login
2. Go to **Agent Console** tab
3. Within 1-2 minutes, findings from the client PC should appear
4. Look for `source: <client-computer-name>` in the finding details

### Uninstall

On the client PC:

```cmd
# Right-click uninstall.bat → Run as Administrator

============================================
   AiBoO Security Log Plugin
   Uninstaller
============================================

[INFO] Stopping any running agent processes...
[OK] Agent processes stopped.
[INFO] Removing scheduled task...
[OK] Scheduled task removed.
[OK] Config file deleted.
[OK] Temporary files cleaned.

============================================
   Uninstall complete!
============================================
```

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Installer fails "not reachable" | Dashboard server may be off — check `http://<ip>:8001/health` |
| No events appearing | Events are collected every 60s — wait 2 minutes |
| Events seen but not showing in dashboard | Check Agent service is running on port 8001 |
| Duplicate events | The plugin deduplicates by EventRecordId automatically |
| "Access Denied" reading Security log | Run installer as Administrator |

---

## Step 9 — Client Demo Walkthrough

Open `http://localhost:3000` → Login with `admin@example.com` / `admin123`

### What you'll see:

**Dashboard Tab:**
- KPI cards: Open Threats, Critical Findings, Online Cameras, Weapon Detections
- Threat feed (latest findings)
- Orchestration panel (Isolate, Lock Perimeter, etc.)
- Each threat has action buttons: Isolate, Auto-respond, Escalate

**Surveillance Tab:**
- Camera grid (add RTSP cameras via + button)
- Detection log
- CV service status indicator

**Agent Console Tab:**
- 6 findings from demo AI agents
- 5 gate decisions with verdicts
- 1 active pseudo-lock (click Restore)
- Correlated alerts
- Test event button to simulate new attacks

**Settings Tab:**
- Service health indicators (Agent, CV, Backend)
- Connection status (Socket connected/disconnected)

---

## Step 9 — Live Attack Simulation

Run these **one at a time** in PowerShell while the client watches the browser:

### Attack 1: SSH Brute Force
```powershell
$token = (Invoke-RestMethod -Uri "http://localhost:4000/api/auth/login" -Method Post -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}').token
$ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
$body = @{
  id = "live_attack_1"
  agent_name = "CyberThreatAgent"
  event_id = "evt_demo_client"
  threat_type = "network_intrusion"
  severity = "critical"
  confidence = 0.96
  summary = "SSH brute force 12,500 pkt/s from 10.0.0.99 — targeting port 22"
  actions = @("alert_dashboard","isolate_asset","pseudo_lock","escalate_soc")
  metadata = @{ src_ip = "10.0.0.99"; signature = "SSH_BRUTE_FORCE" }
  timestamp = $ts
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:4000/api/agent/finding" -Method Post -Headers @{Authorization="Bearer $token"} -ContentType "application/json" -Body $body
```
→ **Browser:** New finding appears in Agent Console + notification popup

### Attack 2: Create a Threat + Auto-Respond
```powershell
$token = (Invoke-RestMethod -Uri "http://localhost:4000/api/auth/login" -Method Post -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}').token
$authH = @{Authorization="Bearer $token"}

# 2a. Create a real threat in MongoDB (returns ObjectId)
$threat = Invoke-RestMethod -Uri "http://localhost:4000/api/threats" -Method Post -Headers $authH -ContentType "application/json" -Body '{"title":"SSH Brute Force In Progress","severity":"critical","source":"firewall","status":"open","asset":"fw-01"}'
$tid = $threat._id
Write-Output "Threat ID: $tid"

# 2b. Auto-respond to it
Invoke-RestMethod -Uri "http://localhost:4000/api/respond/auto" -Method Post -Headers $authH -ContentType "application/json" -Body "{`"threatId`":`"$tid`"}"
```
→ **Browser:** Threat status changes to "investigating" + response log records auto action

### Attack 3: Isolate a Device
```powershell
$token = (Invoke-RestMethod -Uri "http://localhost:4000/api/auth/login" -Method Post -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}').token
Invoke-RestMethod -Uri "http://localhost:4000/api/respond/isolate" -Method Post -Headers @{Authorization="Bearer $token"} -ContentType "application/json" -Body '{"ip":"10.0.0.99"}'
```
→ **Browser:** New pseudo-lock appears in Agent Console

### Attack 4: Check Response Log
```powershell
$token = (Invoke-RestMethod -Uri "http://localhost:4000/api/auth/login" -Method Post -ContentType "application/json" -Body '{"email":"admin@example.com","password":"admin123"}').token
Invoke-RestMethod -Uri "http://localhost:4000/api/agent/response-log" -Headers @{Authorization="Bearer $token"} | ConvertTo-Json
```
```json
[
  {"type":"auto","target":"live_attack_1","status":"pending","triggeredBy":"...","timestamp":"2026-07-18T20:30:00Z"},
  {"type":"isolate","target":"10.0.0.99","status":"pending","triggeredBy":"...","timestamp":"2026-07-18T20:31:00Z"}
]
```

---

## Real Logs (what you'll see in terminals)

### Backend Terminal
```
[INFO] POST /api/agent/finding 200 12.345ms
[INFO] POST /api/respond/auto 201 8.234ms
[INFO] POST /api/respond/isolate 201 5.678ms
[INFO] Socket connected: abc123 (user: admin@example.com)
[INFO] Socket disconnected: abc123 (user: admin@example.com)
```

### Agent Terminal
```
2026-07-18 20:30:00 [INFO] POST /events 200
2026-07-18 20:30:01 [INFO] POST /events 200
```

### CV Terminal
```
2026-07-18 20:30:00 [INFO] Camera added: demo_cam (Demo Camera)
2026-07-18 20:30:01 [INFO] POST /cameras/detections 201
2026-07-18 20:30:02 [INFO] Detection: person (88%) at Demo Camera
2026-07-18 20:30:03 [INFO] Detection: vehicle (92%) at Demo Camera
```

---

## 5-Gate Architecture — Explained for Client

Every finding passes through these gates before action is taken:

```
Finding → [Gate 1: Reputation]  → [Gate 2: Behavioural]  → [Gate 3: Temporal]
                     ↓                    ↓                       ↓
              IP blacklist?         Profile match?          Time anomaly?
                     ↓                    ↓                       ↓
          → [Gate 4: Geospatial] → [Gate 5: Trust] → Decision (Allow/Block)
                     ↓                    ↓
              Location check?       Device trust score?
```

Each gate returns a verdict visible in the Agent Console.

---

## Quick Start (All at Once)

Use the `start-all.bat` script (Windows):
```bash
.\start-all.bat
```

Each service opens its own window. Expected output:
```
============================================
  AiBoO Tri-Gate Defense Platform
============================================

[1/5] Checking MongoDB...
  [OK] MongoDB running

[2/5] Starting Backend (port 4000)...
  [OK] Backend healthy

[3/5] Starting Frontend (port 5173)...
  [OK] Frontend ready

[4/5] Starting CV Service (port 5050)...
  [OK] CV Service healthy

[5/5] Starting Agent (port 8001)...
  [OK] Agent healthy

============================================
  AiBoO is running!
  Dashboard: http://localhost:3000
  Backend:   http://localhost:4000
  Agent API: http://localhost:8001
  CV Service: http://localhost:5050
============================================
```

**Stop all services:**
```bash
.\close-all.bat
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| MongoDB connection refused | Start MongoDB service: `net start MongoDB` |
| Backend EADDRINUSE :4000 | `taskkill /F /PID (Get-NetTCPConnection -LocalPort 4000).OwningProcess` |
| Frontend blank page | Check browser console — likely CORS or API URL mismatch |
| CV service fails to start | Run `pip install ultralytics` — may need PyTorch |
| Agent won't start | Run `pip install fastapi uvicorn` |
| Socket disconnecting | Frontend is refreshing — normal during development |
| "threats.filter is not a function" | Clear localStorage and reload: `localStorage.clear(); location.reload()` |
| 401 on API calls | Token expired — login again: `http://localhost:3000` |
