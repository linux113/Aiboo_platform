# AiBoO Backend — Connection Map & API Reference

## Services Map (All Connected ✅)

```
Frontend (5173) ←→ Node Backend (4000) ←→ MongoDB (27017)
                        ↕ Socket.IO
Frontend (5173) ←→ Real-time events (live)

CV Service (5050) → POST /api/cameras/detections → Node → Socket → Frontend
Agent Service (8000) → POST /api/agent/finding|correlated|gate-decision → Node → Socket → Frontend
```

## All API Endpoints

### Auth
- POST /api/auth/register  — Create account (returns JWT)
- POST /api/auth/login     — Login (returns JWT)
- GET  /api/auth/me        — Get current user (requires Bearer token)

### Cameras
- GET    /api/cameras              — List all cameras
- POST   /api/cameras              — Add camera (admin/analyst)
- PUT    /api/cameras/:id          — Update camera
- DELETE /api/cameras/:id          — Delete camera (admin only)
- PATCH  /api/cameras/:id/toggle   — Enable/disable camera
- GET    /api/cameras/detections   — All detections (from DB)
- POST   /api/cameras/detections   — Post detection (no auth — CV service uses this)
- PATCH  /api/cameras/detections/:id/ack      — Acknowledge detection
- PATCH  /api/cameras/detections/:id/escalate — Escalate detection
- POST   /api/cameras/:id/detect   — Trigger simulated AI detection

### Threats
- GET   /api/threats     — List threats
- POST  /api/threats     — Create threat
- PATCH /api/threats/:id — Update threat
- GET   /api/threats/:id — Get single threat

### Agent (in-memory, no DB)
- POST /api/agent/finding        — Receive from Python agent
- POST /api/agent/correlated     — Receive correlated alert
- POST /api/agent/gate-decision  — Receive gate decision
- POST /api/agent/pseudo-lock    — Receive lock event
- POST /api/agent/pseudo-lock-restore — Receive restore event
- GET  /api/agent/findings       — Frontend reads findings
- GET  /api/agent/correlated     — Frontend reads correlated
- GET  /api/agent/gate-decisions — Frontend reads gate decisions
- GET  /api/agent/pseudo-locks   — Frontend reads locks
- GET  /api/agent/stats          — Summary stats
- POST /api/agent/pseudo-locks/:id/restore — Frontend restore button

### AI Chat
- POST /api/ai/chat    — Chat (OpenAI GPT-4o-mini or fallback)
- POST /api/ai/explain — Explain alert
- GET  /api/ai/analyze — Threat analysis

### Dashboard
- GET /api/dashboard/kpis — KPI metrics

## Socket.IO Events

### Server → Frontend
| Event | When |
|-------|------|
| init:data | On connect (initial snapshot) |
| detection:new | New camera detection |
| alert:critical | Weapon/watchlist detection |
| threat:new | New threat created |
| threat:update | Threat status changed |
| camera:added | Camera added |
| camera:updated | Camera updated |
| camera:deleted | Camera deleted |
| agent:finding | Agent finding received |
| agent:correlated | Correlated alert |
| agent:gate | Gate decision |
| agent:pseudo-lock | Lock applied |
| agent:pseudo-lock-restore | Lock restored |

## Run Order
```
1. mongod                    # MongoDB
2. npm run seed              # Seed DB (first time only)
3. npm run dev               # Node backend (port 4000)
4. python main.py            # Agent service (port 8000)
5. python app.py             # CV service (port 5050)
6. npm run dev               # Frontend (port 5173)
```
