# Aiboo_platform

---

## Multi-OS detection (Windows + Linux)

One AiBoO backend and dashboard now watch both operating systems:

| Machine | Collector | Reads |
|---|---|---|
| Windows PC / server | `agent/` -> `AiBoO-Agent.exe` | Windows Event Log, processes, device health |
| Linux server | `linux-agent/aiboo_linux_agent.py` | auth.log, nginx access/error, MySQL, journalctl |

Both send the same `POST /api/agent/findings` + `/api/agent/gate-decision`
payloads, so alerts, approvals, playbooks, response rules and reports behave
identically. The dashboard marks each endpoint with its OS (🪟 Windows / 🐧 Linux)
on the Endpoints page. See `linux-agent/README.md` for install (no root needed)
and the full detection list.
