# Adaptive PseudoLock Engine – Specification v1.0

**Xenthives.AI Technologies · AiBoO platform · Companion document no. 3 of the AiBoO Project Proposal (Appendix E). The proposal describes PseudoLock in §7.5, §8.3 (Layer 5 – Adaptive Response), §9.5 (Key Feature 4) and §9.7.**

| | |
|---|---|
| Version | 1.0 |
| Status | Implemented. This document describes the code as it ships. |
| Code – agent (does the actions) | `agent/response/real_response_engine.py`, `agent/response/access_control.py`, `agent/agents/pseudo_lock_agent.py`, `agent/core/command_channel.py`, `agent/gates/gate3_adaptive.py` (recommendations) |
| Code – backend (decides when) | `backend/services/pseudolock.service.js` (approvals, playbooks, runs), `backend/services/responseRules.service.js` (response rules), `backend/routes/pseudolock.routes.js`, `backend/sockets/agentChannel.js`, `backend/services/badge.service.js` |
| Code – dashboard | `frontend/src/components/ResponseModule.tsx` (Response screen), `ResponseRules.tsx` (⚙ Rules tab), `DashboardModule.tsx` (one-click playbooks), `TriGateCard.tsx` (Run buttons), `AlertsModule.tsx` (▶ Run playbook) |
| Tests | `backend/tests/pseudolock.test.js`, `backend/tests/responseRules.test.js`, `agent/tests/test_trigate.py`, `agent/tests/test_lock_user_account.py`, `agent/tests/test_test_result_fixes.py` |
| Field test guide | `TRIGATE_TEST_GUIDE.md` §20 (approvals, playbooks) and §21 (response rules) |
| Related | `TRIGATE_SPECIFICATION_v1.0.md`: TriGate decides *how risky* an event is. PseudoLock decides *what to do about it*. |

> **Rule for this document:** every number here is the number in the code. If you change a default, a limit or an action in the files above, change this document too.

---

## 1. Purpose and scope

The proposal says the Adaptive PseudoLock Engine *"converts intelligent security decisions into coordinated defensive actions. Instead of enforcing rigid security policies, the engine recommends or orchestrates adaptive responses based on organizational context, risk level, and predefined governance policies"* (§7.5).

This specification defines:

1. **What PseudoLock can do.** These are the response actions on a Windows PC and in outside systems (§4).
2. **When it does it.** It can recommend, wait for approval, or act automatically, based on the TriGate risk and the settings (§5).
3. **The analyst approval workflow.** This covers pending approvals, who decided, and expiry (§6).
4. **Security playbooks.** These are several steps run in order, with an editor (§7).
   **Response rules** start a playbook automatically, or ask first, when an attack matches (§7.7).
5. **Escalation and notification** (§8).
6. **Safety rules and undo** (§9, §10).
7. **Configuration, audit trail, API and worked examples** (§11–§14).

The proposal lists eight capabilities. This table maps each one to the part of v1.0 that implements it.

| Proposal capability (§7.5) | v1.0 implementation | Section |
|---|---|---|
| Dynamic Access Control | Block IP, disable an account for N minutes (turned back on automatically), disable an account, slow down traffic (throttle) | §4 |
| Session Restriction | Log off a user, lock the screen | §4 |
| Endpoint Isolation | Firewall isolation from an attacker IP, stop a program, decoy port (Lock Perimeter) | §4 |
| Analyst Approval Workflow | **Pending approvals** list: Approve / Reject, who decided, expiry countdown | §6 |
| Incident Escalation | War Room, critical notifications, approval requests sent to every dashboard | §8 |
| Security Playbook Execution | 7 one-click playbooks, plus **multi-step playbooks** (6 built-in, unlimited custom) with an editor | §7 |
| Automated Notification | Dashboard bell for approvals, playbook "notify" steps, failed actions and War Room. Badge-system webhook | §8 |
| Response Orchestration | Playbook runner: actions in order across the dashboard, backend and agent; waits for each result; stops or continues on failure. **Response rules** start the right playbook by attack type, risk, PC, IP type and time of day | §7.3, §7.7 |

**Out of scope for v1.0** (see §15 for details):
- email, Teams or SMS notification;
- NAC / switch quarantine;
- identity-provider (Azure AD / Okta) MFA and session revocation;
- domain accounts.

---

## 2. Design philosophy

| Principle | How v1.0 implements it |
|---|---|
| **A human decides by default** | `auto_response = false` is the default. When TriGate says BLOCK, the actions go to **Pending approvals** and nothing changes on the PC until an admin or analyst presses **Approve**. |
| **Least disruption first** | The built-in playbooks start mild and escalate. For example, they slow traffic down before blocking it. Accounts are disabled **for 30 minutes and turned back on automatically**, not forever. "Contain password guessing" carries on if the account step fails. |
| **Never lock yourself out** | The agent refuses to disable or log off the account it runs as, and refuses built-in system accounts. It never kills critical processes, and never throttles a range that contains the dashboard backend (§9). |
| **Honest results** | An action only shows **Done** when the agent reports `executed`. Failures show the agent's error text. No answer within the time limit shows **No answer … it may still have run**. Quarantine says plainly that it needs NAC instead of pretending. |
| **Explainable and audited** | Every approval records who or what requested it, why (TriGate risk and pattern), who approved or rejected it, when, and the note. It also records the result from the PC and a time-stamped history. Every run records who started it and the status of each step. |
| **Reversible** | Each action has an undo (§10). Temporary actions undo themselves. |
| **No alert storms** | The same action, on the same PC, for the same target that is already pending is **not** added again. It counts the repeat (`seen ×N`) and restarts the timer. |
| **Least privilege** | Viewers can see everything but cannot approve, run or edit. Only actions on the agent's whitelist can be sent. The agent can switch remote commands off completely (`remote_commands = false`). |

---

## 3. Architecture

### 3.1 Position in AiBoO (Layer 5 – Adaptive Response)

```
                     TriGate final decision (Gate 3: risk, verdict, recommended actions)
                                     │
             ┌───────────────────────┴─────────────────────────┐
   auto_response = true                                auto_response = false (default)
             │                                                  │
   Agent runs BLOCK actions itself              Backend: PENDING APPROVAL (one per action)
   (RealResponseEngine)                                        │  Approve (admin / analyst)
             │                                                  ▼
             │          Dashboard one-click ── POST /api/agent/commands ─┐
             │          Playbook runner (backend, step by step) ─────────┤
             │                                                           ▼
             │                                       Command channel (Socket.IO /agent-channel)
             │                                                           │ {cmd_id, action, target, params}
             ▼                                                           ▼
   ┌──────────────────────── Agent on the PC: CommandChannel → whitelist → RealResponseEngine ─┐
   │  firewall rule · disable / enable account · log off · lock screen · QoS throttle ·        │
   │  kill process · decoy port                                                                │
   └───────────────┬───────────────────────────────────────────────┬───────────────────────────┘
                   │ ack: received → executed / failed             │ ActionRecord (POST /api/agent/actions)
                   ▼                                               ▼
     approval / run step = Done / Failed                 Agent Console → Isolation & Termination
```

The backend never changes a PC itself. Only the agent on that PC does. The one exception is **Freeze badge**: the backend calls the badge system's webhook.

### 3.2 Components

| Component | Responsibility |
|---|---|
| `gates/gate3_adaptive.py` → `recommend()` | Picks the recommended actions for each attack pattern and risk level (§5.2). |
| `core/backend_bridge.py` | Sends the final TriGate decision to the backend, **including `auto_response`**, so the backend knows whether a person must approve. |
| `core/command_channel.py` | Keeps a WebSocket connection to the backend. Receives commands, checks the whitelist, and runs the action. Acks `received`, then `executed` with a result, or `failed` with an error. |
| `response/real_response_engine.py` | Maps an action to the field it needs (IP, user, PID, segment), applies the safety rules (§9) and runs the Windows command. Publishes an ActionRecord. |
| `response/access_control.py` | Handles temporary restrictions and throttles. State is saved in `access_control_state.json`, and an expiry check runs every **20 s**, so these survive an agent restart. Also logs users off and locks the screen. |
| `agents/pseudo_lock_agent.py` | Lock Perimeter: a real decoy TCP listener on a random port between 32768 and 60999. It logs every visitor and can be closed with Restore. |
| `backend/sockets/agentChannel.js` | Sends commands to a connected agent and keeps the last **500** commands. Tells listeners about every ack (`onAck`). |
| `backend/services/pseudolock.service.js` | Holds approvals, playbooks and runs. Contains the step runner, the expiry sweeper (every **15 s**) and the TriGate → approval rule. |
| `backend/routes/pseudolock.routes.js` | REST API (§14). |
| `frontend/.../ResponseModule.tsx` | The **Response** screen: Approvals, Playbooks with the editor, and Runs. Also the "Run playbook" dialog used by Alerts. |

**Storage.** The backend uses MongoDB collections `approvals`, `playbooks` and `playbookruns`. Approvals and runs are kept **180 days**.

Without MongoDB (tests, or `ALERT_STORE=memory` / `RESPONSE_STORE=memory`), the same API works in memory. The memory limits are 3000 approvals, 500 playbooks and 1000 runs.

### 3.3 Data contracts

**Command (backend → agent)** and **ack (agent → backend)**:

```json
{ "cmd_id": "cmd_1759390000000_ab12cd", "action": "restrict_identity", "target": "guest", "params": { "minutes": 30 } }
{ "cmd_id": "cmd_1759390000000_ab12cd", "status": "executed", "result": { "message": "Account 'guest' disabled for 30 min ..." } }
{ "cmd_id": "...", "status": "failed", "error": "Refusing to disable 'lalit': it is the account the agent is running as ..." }
```

**Approval:**

```json
{
  "id": "apr_mg8x2k1abcde", "status": "pending",
  "kind": "action",                        "origin": "trigate",
  "title": "Block IP 45.95.147.3 in Windows Firewall",
  "action": "block_access", "target": "45.95.147.3", "params": {}, "endpoint": "gorilla",
  "reason": "TriGate BLOCK (risk 66): Password guessing - 6 wrong passwords for guest",
  "risk": 66, "level": "high", "verdict": "block", "pattern": "brute_force",
  "alertId": "tg_ev1", "eventIds": ["ev1"], "occurrences": 1,
  "requestedBy": "TriGate (gorilla)", "requestedAt": "2026-10-02T10:00:00Z",
  "expiresAt": "2026-10-02T10:30:00Z", "expiresMinutes": 30, "expiresInSeconds": 1795,
  "decidedBy": null, "decidedAt": null, "note": "",
  "cmdId": null, "result": null, "error": null, "finishedAt": null,
  "history": [{ "at": "...", "by": "TriGate", "what": "requested" }]
}
```

- `kind` is `action` or `playbook_step`.
- `origin` is `trigate`, `playbook` or `manual`.

**Playbook** (see §7):

```json
{ "id": "pb_...", "name": "Throttle then block", "description": "...", "enabled": true, "version": 2,
  "steps": [
    { "type": "action",   "action": "throttle_segment", "target": "{ip}", "params": { "kbps": 512, "minutes": 10 }, "onFailure": "stop" },
    { "type": "approval", "message": "Block {ip} on {pc}?", "expiresMinutes": 5 },
    { "type": "action",   "action": "block_access", "target": "{ip}", "onFailure": "stop" },
    { "type": "notify",   "level": "critical", "message": "done {ip}" },
    { "type": "wait",     "seconds": 30 } ],
  "createdBy": "analyst@company", "updatedBy": "admin@company" }
```

**Run:**

```json
{ "id": "run_...", "playbookId": "...", "playbookName": "...", "endpoint": "gorilla",
  "vars": { "ip": "203.0.113.9", "pc": "gorilla" }, "alertId": "tg_ev1",
  "status": "waiting_approval", "current": 1,
  "steps": [ { "label": "Slow down traffic (throttle): 203.0.113.9 (10 min)", "status": "done", "message": "...", "error": null, "approvalId": null },
             { "label": "Wait for approval: Block 203.0.113.9 on gorilla?", "status": "waiting", "approvalId": "apr_..." } ],
  "startedBy": "lalit@company", "startedAt": "...", "finishedAt": null, "message": "" }
```

- Run `status` is one of `running`, `waiting_approval`, `done`, `failed`, `stopped` or `cancelled`.
- Step `status` is one of `pending`, `running`, `waiting`, `done`, `failed` or `skipped`.

---

## 4. Response action catalogue

These are the actions the dashboard, approvals and playbooks can send. Anything else is refused by the agent's whitelist (`REMOTE_ALLOWED_ACTIONS` in `core/orchestrator.py`).

| Action id | Name in the dashboard | What happens on the PC | Target | Parameters | Undo |
|---|---|---|---|---|---|
| `block_access` | Block IP (Windows Firewall) | `netsh advfirewall` rule `AiBoO_Block_<ip>_<id>`: blocks **incoming** traffic from the IP, all protocols | IP address | – | Delete the rule in Windows Firewall |
| `isolate_asset` | Isolate – cut the PC off from an IP / Isolate Host | Rule `AiBoO_Isolate_<ip>_<id>`: blocks incoming traffic from the IP | IP address | – | Delete the rule |
| `throttle_segment` | Slow down traffic (throttle) | Windows QoS policy `AiBoO-Throttle-<range>` (`New-NetQosPolicy`, ActiveStore): limits traffic to the IP or range | IP or CIDR | `kbps` 256 (64–100000), `minutes` 30 (1–1440) | Automatic when the time is up, `remove_throttle`, or a reboot |
| `remove_throttle` | Remove slow-down | Removes the AiBoO QoS policy for that range | IP or CIDR | – | – |
| `restrict_identity` | Disable account for N minutes / Restrict Account | `net user <name> /active:no` and logs off its sessions. **Turned back on automatically** when the time is up, even after an agent restart. An account that was already disabled is left alone and not turned back on | Windows user | `minutes` 30 (1–1440) | Automatic, or `lift_restriction` |
| `lift_restriction` | Re-enable account now | Turns the account back on, but only one that AiBoO disabled | Windows user | – | – |
| `revoke_identity` | Disable account / Quarantine Identity | `net user <name> /active:no`, then checked again with `net user` | Windows user | – | `net user <name> /active:yes` |
| `force_logout` | Log off user | Ends all Windows sessions of the user (WTS logoff) | Windows user | – | User signs in again |
| `step_up_auth` | Lock the screen (sign in again) | Locks the Windows screen. The person must type the password, PIN or Windows Hello again. Windows has no MFA prompt of its own | Windows user (for the record) | – | User unlocks |
| `terminate_process` | Stop a program | Kills the process by PID, or every process with that name. Uses the never-kill list (§9) | PID or program name | – | Start the program again |
| `pseudo_lock` | Open decoy port / Lock Perimeter | Opens a real decoy TCP listener on a random port between 32768 and 60999 and logs every visitor | Label (optional) | – | Agent Console → Locks → **Restore** |
| `freeze_badge` | Freeze door badge | **Backend** POSTs `{action:'freeze_badge', badge_id, reason, requested_by, requested_at}` to `BADGE_WEBHOOK_URL` (8 s timeout, optional Bearer `BADGE_WEBHOOK_TOKEN`) | Badge or employee ID | – | Done in the badge system |
| `quarantine_device` | – (not offered in playbooks) | **Refused** with "needs a network access control (NAC) / switch integration, which is not connected" | – | – | – |
| `notify_security` | – | Agent log only. Use a playbook **notify** step instead (§8) | – | – | – |

**How targets are checked.** The backend checks every target before sending; the agent checks again.

| Target type | Rule |
|---|---|
| IP | A valid IPv4 or IPv6 address |
| Range | IP or IP/prefix |
| User | 1–64 characters: letters, digits, space, and `. _ - @ \ $` |
| Process | Digits (a PID), or a program name |
| Badge | 1–120 characters |

---

## 5. Choosing the response: risk, context and policy

### 5.1 Three response modes

The mode is set **per PC** in `agent/config.ini` (`auto_response`), plus the backend settings in §11.

| TriGate verdict | `auto_response = false` (default) | `auto_response = true` |
|---|---|---|
| **BLOCK** (risk ≥ 55) | Each executable recommendation becomes a **pending approval** (§6). Run buttons are also on the TriGate card and in the alert. | The agent runs the executable recommendations **immediately**. No approval is created, so nothing runs twice. |
| **HOLD** (35–54) | Alert plus recommendations with Run buttons. An approval is created only if `APPROVAL_VERDICTS` contains `hold`. | Same as on the left. Nothing runs automatically. |
| **PASS** (< 35) | Logged only | Logged only |

The agent puts `auto_response` in every decision it sends, so the backend knows which mode applies. An older agent doesn't send it; in that case the backend uses the value from that agent's last status report, and if that is unknown, assumes `false`.

### 5.2 Recommended actions by pattern (`recommend()` in `gate3_adaptive.py`)

| Pattern | Recommendation (in this order) |
|---|---|
| Any pattern, level LOW | `log`: no action |
| brute_force, failed_logon, account_lockout, network_intrusion (with an IP) | `block_access` on the source IP |
| brute_force, failed_logon, account_lockout on an account that exists | `restrict_identity` on that account, 30 min |
| admin_group_add, account_created | `revoke_identity` on the **new or changed** account (never the admin who made the change) |
| behavioral_anomaly / anomalous_behavior | `force_logout`. At HIGH or CRITICAL, also `restrict_identity` for 30 min |
| threat_intel_alert | `block_access` on the public IP, `terminate_process` on the PID, **or** `throttle_segment` on the IP |
| log_cleared, audit_policy_changed, service_installed, scheduled_task | manual check (text only) |
| CRITICAL + evidence / persistence / admin / malware pattern | `isolate_asset` |
| Any non-LOW | `notify_security` |

### 5.3 What may run automatically or become an approval

These are the same four actions in both cases:

- `block_access`
- `restrict_identity`
- `revoke_identity`
- `isolate_asset`

They come from `_EXECUTABLE` in the agent and `TRIGATE_APPROVAL_ACTIONS` in the backend.

- Log off, kill a process and throttle always stay a person's decision: a one-click button, or a playbook.
- A recommendation whose target doesn't fit the action is skipped. For example, `isolate_asset` with the target "this PC" has no IP.

### 5.4 Governance policy in v1.0

The policy is made of these settings:

- `auto_response` and `remote_commands` per PC;
- `APPROVAL_VERDICTS`, `APPROVALS_FROM_TRIGATE`, `APPROVAL_EXPIRY_MINUTES` and `APPROVAL_FOUR_EYES` in the backend;
- the PC importance (TriGate Gate 3);
- roles: only admin and analyst may approve, run or edit.

On top of these, **response rules** (§7.7) let an admin or analyst decide per attack type, risk, PC, PC importance, IP type and time of day whether a playbook runs automatically, waits for approval, or only notifies.

---

## 6. Analyst approval workflow

### 6.1 Life cycle

```
                 ┌──────────── Reject ────────────► REJECTED   (nothing runs)
                 │
  requested ─► PENDING ──── Approve ───┬─ action ──► RUNNING ──► DONE    (agent: executed)
  (TriGate,      │                     │                    └──► FAILED  (agent error / offline / no answer)
   playbook,     │                     └─ playbook step ──► APPROVED  (the run continues)
   by hand)      ├── timer runs out ──────────────► EXPIRED    (nothing runs; a playbook stops)
                 └── its playbook run cancelled ──► CANCELLED
```

### 6.2 Rules

| Rule | Value |
|---|---|
| Who may approve or reject | `admin` and `analyst` roles. Viewers see the list read-only (HTTP 403 if they try). |
| Expiry | `APPROVAL_EXPIRY_MINUTES`, default **30** (1–1440). A playbook approval step can set its own value. |
| Expiry check | A sweeper runs every **15 s**. Opening the list also checks. Approving after the time is up returns **409 "Too late – this approval has expired"**. |
| Repeats | The same PC + action + target while pending: `occurrences + 1`, the timer restarts and the higher risk is kept. Not a new row. |
| Late decisions | A TriGate decision older than the expiry time does not create an approval. This happens when the agent sends old queued events after being offline. |
| Deciding twice | Refused (409 "Already done by …"). |
| Four-eyes (optional) | With `APPROVAL_FOUR_EYES=true`, the person who requested an approval cannot approve it (403). TriGate requests can be approved by anyone with the role. |
| Agent offline when approved | Status **Failed**: "PC 'x' is not connected – start the agent on that PC and try again". |
| No answer | After `PLAYBOOK_ACTION_TIMEOUT_SECONDS` (default **90**): Failed, "No answer … it may still have run, check Agent Console". |

### 6.3 What is recorded (audit trail)

Every approval keeps the following:

- requested by, requested at, reason, risk and level, pattern;
- the link to the alert (`tg_<event_id>`) and the TriGate event ids;
- decided by, decided at, and the note;
- the agent command id, and the result or error, with the finish time;
- a time-stamped `history` (requested, repeated, approved or rejected, executed or failed, expired or cancelled).

The dashboard shows all of this in **Response → Approvals → History**.

---

## 7. Security playbooks

### 7.1 Step types

| Step | What it does | Fields |
|---|---|---|
| **action** | Runs one action from §4 on the chosen PC and waits for the agent's answer | `action`, `target` (variables allowed), `params`, `onFailure` = `stop` (default) or `continue` |
| **approval** | Creates a pending approval and **pauses the run**. Approve: the next step runs. Reject or expiry: the run **stops** and the remaining steps are skipped | `message` (variables allowed), `expiresMinutes` (default `APPROVAL_EXPIRY_MINUTES`) |
| **notify** | Sends a message to every open dashboard (the bell) | `message`, `level` = `info`, `warning` or `critical` |
| **wait** | Pauses | `seconds` 1–3600 |

### 7.2 Variables

You can write these in targets and messages. They are filled in when the run starts.

| Variable | Meaning | Filled from an alert |
|---|---|---|
| `{ip}` | IP address | alert source IP |
| `{user}` | Windows user | alert subject or entity |
| `{pc}` | PC (endpoint) chosen for the run | alert PC |
| `{pid}` | Process ID | alert data, if present |
| `{badge}` | Badge or employee ID | – |
| `{alert}` | Alert id | the alert |

`{pc}` and `{alert}` are automatic. The run form asks only for the other variables the playbook uses.

### 7.3 How a run executes

1. **Start.** These checks happen first:
   - the playbook is enabled;
   - a PC is chosen if any action needs one, and that PC is **online**;
   - every needed variable is filled in;
   - every filled-in target is valid (for example, `{ip}` = "abc" is refused **before** anything runs).

   The run stores a copy of the steps, so later edits to the playbook don't change a running run.
2. **Steps run one after the other**, never in parallel. Each step is saved and sent live to the dashboard (`run:updated`).
3. **Action step.** The command is sent and the run waits for `executed` or `failed`, up to 90 s.
   - On failure with `onFailure = stop`, the run becomes **failed** and the remaining steps are **skipped**.
   - With `continue`, the step is marked failed and the run goes on.
4. **Approval step.** The run status becomes `waiting_approval` and the approval appears in Pending approvals with the run's name. The decision resumes or stops the run (§6).
5. **Cancel.** Admin or analyst can cancel. A pending approval of that run becomes **cancelled**. Steps already done are **not** undone (the dashboard warns about this).
6. **Backend restart.** A run that was in the middle of a step is marked **failed** ("Backend restarted while this playbook was running – check the PC"). A run waiting for approval simply continues when someone approves.

### 7.4 Editor and validation

The editor is at Response → Playbooks → **＋ New playbook**, or **⧉ Copy & edit**. You can:

- add steps of the four types and change their order (↑ ↓);
- remove a step;
- choose the action and fill in the target and parameters;
- choose what happens if a step fails;
- tick Enabled.

The backend checks the playbook again on save:

| Check | Rule |
|---|---|
| Name | Required, max 80 characters |
| Steps | 1–15 steps |
| Action | Must be in the catalogue |
| Target | Required unless optional. A target without variables must be valid. Unknown variables (for example `{ipaddr}`) are refused |
| Parameters | Clamped to their ranges |
| Wait | 1–3600 s |
| Notify | Needs a message |

All errors are listed under the editor. Built-in playbooks cannot be changed or deleted; copy them instead. Each saved change increases `version`.

### 7.5 Built-in playbooks

| Id | Name | Steps |
|---|---|---|
| `builtin_password_guessing` | Contain password guessing | 1 block `{ip}` → 2 disable `{user}` for 30 min (continue if it fails) → 3 notify (warning) |
| `builtin_new_admin` | Suspicious new admin / new account | 1 **approval** (30 min) → 2 disable `{user}` → 3 log off `{user}` (continue) → 4 notify (critical) |
| `builtin_bad_ip` | Known-bad IP (threat intelligence) | 1 throttle `{ip}` 256 kbit/s for 30 min → 2 **approval** → 3 block `{ip}` → 4 notify |
| `builtin_stop_program` | Stop program talking to a bad IP | 1 stop `{pid}` → 2 block `{ip}` → 3 notify |
| `builtin_compromised_pc` | Compromised PC – escalate and isolate | 1 notify (critical, "war room") → 2 **approval** (15 min) → 3 isolate from `{ip}` → 4 decoy port (continue) → 5 notify |
| `builtin_safe_test` | Safe test (changes nothing on the PC) | 1 notify → 2 wait 5 s → 3 **approval** (10 min) → 4 notify |

When **▶ Run playbook** is pressed on an alert, the suggested playbook depends on the pattern:

| Alert pattern | Suggested playbook |
|---|---|
| brute force, failed logon or lockout | Contain password guessing |
| admin group or new account | Suspicious new admin |
| threat intel | Known-bad IP, or Stop program when a PID is known |
| log cleared, audit change, service, task, malware or network intrusion | Compromised PC |
| anything else | Safe test |

### 7.6 One-click playbooks (Dashboard)

The Dashboard also has seven single-action buttons:

- Isolate Host
- Lock Perimeter
- Quarantine Identity
- Restrict Account
- Throttle Segment
- Freeze Badge
- Open War Room

They act immediately after a confirm and do not use the approval list.

### 7.7 Response rules ("WHEN this happens → THEN do that")

A response rule starts a playbook by itself when a TriGate decision matches. Rules are made on **Response → ⚙ Rules** (admin and analyst; viewers can only look).

**When rules are checked.** For every TriGate decision the agent sends (`POST /api/agent/gate-decision`):

1. Only **BLOCK** and **HOLD** decisions are checked. PASS never triggers a rule.
2. Old decisions replayed from an agent's offline queue are ignored. "Old" means older than `APPROVAL_EXPIRY_MINUTES` (default 30 min), the same check the approvals use.
3. The **enabled** rules are checked **from top to bottom** (the order on the screen, changed with ↑ ↓). The **first** rule that matches is used; the rules below it are not checked.
4. If no rule matches, or the rule only notifies, is in test mode, or is skipped, the normal behaviour of §5.1 follows (TriGate BLOCK → pending approvals).
5. If a rule **ran** a playbook, **asked** for one, or is in **cooldown**, the normal TriGate approvals are **not** created, so the same thing is not asked twice.
6. Rules work whatever `auto_response` is set to. A PC with `auto_response = true` already acts by itself, so a rule may then repeat an action; the screen warns about this.

**WHEN – conditions (all must be true)**

| Condition | Values | Empty / default means |
|---|---|---|
| Attack type | TriGate patterns: password guessing (`brute_force`), failed logon, account locked out, admin group add, account created / deleted, RunAs with someone else's password, log cleared, audit policy changed, service installed, scheduled task, known-bad IP, network intrusion, malware, malicious code in memory, unusual behaviour (2), impossible location, attack chain, identity problem, insider activity, phishing | any type |
| Risk at least | 0–100 | 55 |
| TriGate verdict | BLOCK and/or HOLD | BLOCK |
| Only these PCs | PC names (endpoint ids) | all PCs |
| PC importance | low / normal / high / critical (TriGate Gate 3) | any |
| Where the attack comes from | any · internet IP only · office / private IP only · no IP (local, at the keyboard) | any |
| Time of day | any · office hours only · outside office hours only. Office hours = `OFFICE_HOURS` (default `8-20`: 08:00 up to 19:59), on the **PC's clock** (`local_hour` from Gate 1) | any time |

**THEN – mode**

| Mode | What happens | Shown as |
|---|---|---|
| ⚡ **Run automatically** | The playbook starts at once on the PC where the attack was seen. Run "started by Rule "name"", trigger `rule` | Runs tab, badge "⚙ automatic (rule)" |
| ✋ **Ask first** | A pending approval of kind `playbook_start`: "Rule "X" wants to run "P" on PC (ip …, user …)". **Approve & start** starts the run ("started by Rule "X" (approved by Y)"). Reject starts nothing. Expiry, notes, four-eyes and "seen ×N" work as in §6 | Approvals tab |
| 📣 **Notify only** | A bell message (info, warning or critical) on every open dashboard. Nothing is changed | Bell |

**Variables.** The playbook's `{ip}`, `{user}`, `{pid}` and `{pc}` are filled in from the attack:

- `ip` = the source IP, only if it is a real public or private address;
- `user` = the subject (else the entity) of the event;
- `pid` = the process id, if the event has one;
- `pc` = the PC that reported it.

If the playbook needs a variable the attack does not have, the rule records **skipped** and does nothing. Example: wrong passwords typed at the PC itself have no IP. `{badge}` never comes from an attack, so badge playbooks only make sense by hand. Targets are checked (§4) before anything is sent.

**Safety**

| Setting | Default | Effect |
|---|---|---|
| 🧪 Test mode | **on** for a new rule | The rule only writes "TEST MODE – would have: run P" in the Activity list. Nothing runs and the normal approvals still appear |
| Cooldown | 30 min (0–1440) | The same rule + PC + IP + user is handled only once in this time; repeats are logged as **cooldown** |
| Max automatic runs per hour | 10 (1–100) | Above this a "Run automatically" rule **asks** instead, and a warning goes to every dashboard. This protects against a rule that is too wide |
| Test against old alerts | last 30 days | Shows how many TriGate alerts the rule would have matched (and about how many per day), up to 15 examples, and the most common reasons the others did not match. More than 20 per day gives a warning |
| On / off switch | on | An "off" rule is never checked |
| Playbook in use | – | A playbook used by a rule cannot be deleted (409). A rule whose playbook is off or missing records **skipped** and warns |

**Activity.** Every match is recorded (kept 90 days) with time, rule, PC, attack, variables and outcome. The outcomes are:

- **ran**, **asked** or **notified**;
- **test** (test mode);
- **cooldown**;
- **skipped**: a variable is missing, the target is invalid, or the playbook is off;
- **failed**: for example the PC is not connected.

The rule card shows "matched N× · last …".

**Storage.** Rules are kept in collection `responserules` and activity in `ruleevents` (MongoDB). Both are in memory when `ALERT_STORE=memory` / `RESPONSE_STORE=memory` or MongoDB is not connected. Cooldown timers are kept in memory, so a backend restart resets them. Saving a rule or switching it on/off also restarts its cooldowns, so leaving test mode works at once.

---

## 8. Escalation and notification

| Channel | Triggered by | Who sees it |
|---|---|---|
| Bell: **"Approval needed"** | Every new approval (`approval:new`) | Every open dashboard. The **Response** tab shows an amber badge with the number pending (refreshed live, and every 60 s) |
| Bell: playbook messages | Playbook **notify** steps (`pseudolock:notify`, info, warning or critical) | Every open dashboard |
| Bell: **response rules** | A "Notify only" rule; a rule that reached its hourly limit; a rule that could not start its playbook | Every open dashboard |
| Bell: **"Action Failed"** | An ActionRecord with status failed | Every open dashboard |
| **War Room** | Dashboard button (`war-room:opened`) | Every open dashboard, critical |
| Badge system | Freeze badge (one-click or playbook step) | The company's door system, through the webhook |
| Agent window | Every action (coloured log) | The person at the PC |

Email, Teams and SMS are not part of v1.0 (§15).

---

## 9. Safety rules

| Rule | Where |
|---|---|
| Refuses to disable or log off **the account the agent runs as**, and built-in Windows system accounts | `real_response_engine._refuse_if_self_or_system`, `execute_remote_action` |
| Strips `THISPC\` / `.\` from user names. Refuses domain accounts with a clear message (must be done on the domain controller) | `_to_local_account_name`, `_lock_user_account` |
| Checks with `net user` after disabling, and reports **Failed** if Windows still shows the account active | `_lock_user_account` |
| `restrict_identity` turns back on **only** accounts that AiBoO disabled. An account that was already disabled is left alone | `access_control.restrict_identity` |
| Restrictions and throttles survive an agent restart (`access_control_state.json`) and are undone on time (checked every 20 s) | `access_control` |
| **Never-kill list**: System, smss, csrss, wininit, winlogon, services, lsass, dwm, svchost and others, plus the agent itself and its parent | `_PROTECTED_PROCESS_NAMES`, `_is_kill_allowed` |
| Throttle refuses ranges larger than /8 ("almost the whole internet") and ranges that contain the dashboard backend | `access_control._check_segment` |
| Firewall rules and QoS policies are named `AiBoO_*` / `AiBoO-Throttle-*`, so they can be found and removed | handlers |
| Only whitelisted actions are accepted from the dashboard. `remote_commands = false` switches remote actions off completely | `REMOTE_ALLOWED_ACTIONS`, `command_channel.py` |
| Agents must present `AGENT_API_KEY` to connect. An ack from a different PC than the one the command went to is ignored | `agentChannel.js` |
| Viewers cannot approve, run, edit or cancel (403) | `pseudolock.routes.js` |
| Targets are checked before sending (backend) and before running (agent) | §4 |
| Response rules: test mode on by default, cooldown, max automatic runs per hour (then ask), only fresh decisions, first matching rule only | `responseRules.service.js`, §7.7 |

---

## 10. Undo and reversibility

| Action | Undo |
|---|---|
| Disable account for N min | Automatic when the time is up. Early: action `lift_restriction` (Agent Console → **Lift restriction**, or a playbook step) |
| Throttle | Automatic when the time is up, `remove_throttle`, or a reboot (the policy is in the ActiveStore) |
| Decoy port | Agent Console → Locks → **Restore** |
| Block / isolate IP | Windows Defender Firewall → Inbound Rules → delete `AiBoO_Block_…` / `AiBoO_Isolate_…` |
| Disable account | `net user <name> /active:yes` (as Administrator) |
| Log off / lock screen / stop program | Nothing to undo: the user signs in again or starts the program again |

---

## 11. Configuration

**Agent – `agent/config.ini` (all optional)**

| Key | Default | Effect |
|---|---|---|
| `auto_response` | false | true: the agent runs BLOCK actions itself and no approvals are created. false: approvals (§5.1) |
| `remote_commands` | true | false: the PC ignores all dashboard, approval and playbook actions |

**Backend – `backend/.env` (all optional)**

| Key | Default | Effect |
|---|---|---|
| `APPROVAL_EXPIRY_MINUTES` | 30 | How long an approval waits (1–1440) |
| `APPROVALS_FROM_TRIGATE` | true | false: TriGate BLOCK no longer creates approvals (Run buttons only) |
| `APPROVAL_VERDICTS` | block | Which verdicts create approvals: `block` or `block,hold` |
| `APPROVAL_FOUR_EYES` | false | true: the person who requested cannot approve their own request |
| `PLAYBOOK_ACTION_TIMEOUT_SECONDS` | 90 | How long to wait for the agent's answer per action (5–600) |
| `BADGE_WEBHOOK_URL` / `BADGE_WEBHOOK_TOKEN` | – | Badge system for Freeze badge |
| `RESPONSE_STORE` | – | `memory`: keep approvals, playbooks and rules in memory (testing only) |
| `OFFICE_HOURS` | 8-20 | Office hours for response rules (start hour – end hour, PC's clock) |
| `REPORT_TZ` | server time | Time zone used for "Test against old alerts" on alerts that do not record the PC's hour |

---

## 12. Presentation (dashboard)

The **Response** tab is next to Alerts. It has an amber badge showing how many approvals are pending.

| Screen | Shows |
|---|---|
| **Approvals → Pending** | One card per request: what will happen (action → target, PC), why (origin, risk, pattern, reason), `seen ×N`, a **live countdown** turning orange in the last 5 minutes, and the exact expiry time. Has a note field and **✔ Approve / ✖ Reject** buttons |
| **Approvals → History** | Status (Done, Failed, Rejected, Expired, Cancelled), **Approved / Rejected by whom and when**, the note, the result from the PC or the error, and the full history |
| **Playbooks** | Built-in and custom cards with numbered steps and what they need. Buttons: ▶ Run, ⧉ Copy & edit, ✎ Edit, 🗑 Delete. Opens the editor (§7.4) |
| **Run dialog** | Pick a playbook, a PC (online PCs suggested) and the needed variables. When opened from an alert, these are filled in |
| **Runs** | Last 50 runs: status, PC, who started it, variables, each step with ✅ / ❌ / ⏳ / – and its message or error, and Cancel. Refreshes live, and every 3 s while something runs |
| **Alerts → alert → ▶ Run playbook** | The run dialog with the suggested playbook and the alert's IP, user and PC |
| **⚙ Rules** | Short explanation, **＋ New rule** or **start from an example** (4 ready examples), one card per rule in check order (#1, #2…) with WHEN / THEN in plain words, mode, ON/OFF, 🧪 test mode, cooldown, max per hour, "matched N×". Buttons ↑ ↓, Switch on/off, ✎ Edit, 🗑, 🔍 Test against old alerts. Below: the **Activity** list with links to the run or approval |
| **Rule editor** | Name, ON, test mode; WHEN (attack-type tick boxes, risk, BLOCK/HOLD, PC importance, PCs with online-PC chips, IP type, time of day); THEN (three mode cards, playbook, what it needs and when it is skipped); SAFETY (cooldown, max per hour); Save and Test against old alerts. Warns "This rule will change PCs without asking anyone" for an automatic rule outside test mode |

---

## 13. Worked examples

These come from the automated end-to-end test with a simulated agent (`backend/tests/pseudolock.test.js` and the dashboard click-through). The field test on a Windows PC follows `TRIGATE_TEST_GUIDE.md` §20.

**A. Password guessing, `auto_response = false`**

1. TriGate decides **BLOCK, risk 66** for 6 wrong passwords for `guest` from `45.95.147.3` on PC `gorilla`.
2. Recommended: block IP, disable `guest` for 30 min, isolate "this PC", notify.
3. **Two** pending approvals appear:
   - "Block IP 45.95.147.3 in Windows Firewall";
   - "Disable account 'guest' for 30 min".

   Isolate is skipped because it has no IP; notify is not an action. Both expire in 30:00.
4. The same attack comes again, so the block approval shows **seen ×2**. There is no third row and the timer restarts.
5. The analyst writes the note "confirmed attack from internet" and presses **Approve** on the block. The status goes Running, then **Done on the PC**. History shows "Approved by lalit@company".
6. The analyst presses **Reject** on the restriction. Nothing is sent to the PC. History shows "Rejected by lalit@company".

**B. Same attack, `auto_response = true`.** The agent blocks and restricts by itself. **No** approvals are created, so nothing runs twice.

**C. Custom playbook "Throttle then block"** (throttle 512 kbit/s for 10 min → approval for 5 min → block → notify):
- Run 1: the throttle runs, then the run **waits for approval**. A second analyst approves, the block is sent, and the run is **done**.
- Run 2: the approval is **rejected**, so the run is **stopped**. The block is never sent, and the last two steps are *skipped*.
- Run 3: **cancelled** while waiting, so its approval becomes *cancelled*.

**D. Failure handling, "Contain password guessing":**
- If step 1 (block) fails, the run is **failed** and steps 2 and 3 are skipped.
- If step 2 (disable account, `continue`) fails because the user isn't found, the run is still **done** with steps ✅ ❌ ✅.
- If the agent never answers, the step fails with "No answer from 'gorilla' in 90 s".

**E. Expiry.** An approval nobody answers becomes **Expired** after its time. Approving it then returns "Too late". A playbook waiting on it **stops** with "Nobody approved in time (expired)".

**F. Response rule "Stop password guessing"** (attack type password guessing, risk ≥ 55, BLOCK, run "Contain password guessing" automatically, cooldown 30 min). From `backend/tests/responseRules.test.js`:
- Attack from `45.95.147.3` on `gorilla` for user `lalit`: the playbook runs by itself: block `45.95.147.3`, then disable `lalit` for 30 min. The run says "started by Rule "Stop password guessing"". **No** TriGate approvals appear.
- The same attack again within 30 min is logged as **cooldown**. An attack from another IP runs again.
- In **test mode** nothing is sent; the Activity says "would have: run "Contain password guessing"", and the two normal approvals appear.
- In **Ask first** mode, one approval "Rule … wants to run …" appears. Approve starts the run "(approved by analyst@test)"; reject starts nothing.
- With max 2 per hour, the third attack becomes an approval with "Limit of 2 automatic runs per hour reached – asking instead".
- Wrong passwords typed at the PC itself (no IP) are **skipped** ("This event has no ip"), and the normal approval to disable the user appears.

---

## 14. API reference

All routes are under `/api/pseudolock` and need a login (JWT). Write routes need the admin or analyst role.

| Method and path | Purpose |
|---|---|
| `GET /catalog` | Actions, targets, parameters, variables and settings (used by the editor) |
| `GET /approvals?status=pending\|all\|done,failed…&limit=` | List approvals (newest first; each has `expiresInSeconds`) |
| `GET /approvals/count` | `{ pending }` |
| `GET /approvals/:id` | One approval |
| `POST /approvals` | Ask for approval of one action: `{action, target, params, endpoint, reason, expiresMinutes, alertId}` |
| `POST /approvals/:id/approve` / `reject` | `{ note }` |
| `GET /playbooks`, `GET /playbooks/:id` | Built-in and custom, each with `variables` and `needsPc` |
| `POST /playbooks`, `PUT /playbooks/:id`, `DELETE /playbooks/:id` | Create, change or delete (400 with `errors[]` if invalid) |
| `POST /playbooks/:id/run` | `{ endpoint, vars: {ip, user, pid, badge}, alertId }` → 202 with the run |
| `GET /runs?limit=&status=`, `GET /runs/:id` | Runs |
| `POST /runs/:id/cancel` | Cancel a running or waiting run |
| `GET /rules` | Response rules in check order |
| `POST /rules`, `PUT /rules/:id`, `DELETE /rules/:id` | Create, change or delete a rule: `{name, description, enabled, testMode, mode: auto\|ask\|notify, playbookId, notifyLevel, conditions: {patterns[], minRisk, verdicts[], pcs[], importance[], ipKind: any\|internet\|office\|none, hours: any\|office\|off}, cooldownMinutes, maxPerHour}` (400 with `errors[]`) |
| `POST /rules/:id/enabled` | `{ enabled }` |
| `POST /rules/reorder` | `{ ids: [first, second, …] }` |
| `POST /rules/preview` | `{ conditions, days }` → `{checked, matched, perDay, samples[], notMatchedBecause[]}` (any logged-in user) |
| `GET /rules/activity?ruleId=&limit=` | What the rules did, newest first |

These Socket.IO events go to dashboards:

- `approval:new`
- `approval:updated`
- `run:updated`
- `playbook:updated`
- `rule:updated`, `rule:event`
- `pseudolock:notify`
- `command:sent`

Existing PseudoLock routes under `/api/agent`:

- `POST /commands` (one-click actions)
- `GET /playbooks/status`
- `POST /playbooks/freeze-badge`
- `POST /war-room`
- `POST /pseudo-locks/:id/restore`

---

## 15. Limitations and roadmap (v1.x → v2)

| Item | Status in v1.0 | Planned |
|---|---|---|
| Email / Teams / SMS notification | Dashboard bell and badge webhook only | Notification channels for approvals, critical alerts and playbook notify steps |
| Response rules | Per PC name and PC importance; cooldown timers reset when the backend restarts; one rule per decision | PC groups / tags, rules that run several playbooks, rule change history |
| Device quarantine (NAC / switch port) | Refused with an honest message | NAC / switch integration |
| MFA challenge and session revocation | Lock screen / Windows logoff on the PC | Identity provider (Azure AD / Entra ID, Okta) APIs |
| Domain accounts | Refused (local accounts only) | Through the domain controller / IdP |
| Isolation | Inbound firewall block of one IP | Full isolation (inbound and outbound, allow only the AiBoO backend) |
| Approvals | One approver; optional four-eyes rule | Several approvers, approval groups, escalation when an approval is about to expire |
| Undo of block rules from the dashboard | Done by hand in Windows Firewall | An "Unblock" button (`allow_access`) |
| Playbooks across several PCs | One PC per run | Fan-out to a group of PCs |
| SOAR / ticketing integration | – | ServiceNow / Jira tickets from runs and approvals |

---

## 16. Verification

- **Backend:** `cd backend && npm test`. `tests/pseudolock.test.js` has 11 end-to-end tests covering:
  - TriGate → approvals;
  - duplicates and repeats;
  - auto_response, HOLD and replayed decisions;
  - roles;
  - approve, reject, failure and timeout;
  - expiry and the four-eyes rule;
  - built-in playbooks;
  - runs with stop or continue;
  - the editor's validation, create, edit, disable and delete;
  - approval steps approved, rejected, expired and cancelled.

  `tests/responseRules.test.js` has 11 tests covering:
  - validation and roles;
  - automatic run with the attack's IP and user, and no duplicate approvals;
  - cooldown;
  - no match → normal approvals;
  - test mode and notify mode;
  - ask → approve / reject;
  - the hourly limit;
  - missing variable, rule order and reordering;
  - IP type, office hours and PC importance;
  - replayed decisions;
  - test against old alerts.
- **Agent:** `cd agent && python -m pytest tests` (includes "bridge tells the backend whether the agent runs BLOCK actions itself" and every safety rule).
- **Field test:** `TRIGATE_TEST_GUIDE.md` §20 and §21, on a real Windows PC.

## 17. Version history

| Version | Date | Change |
|---|---|---|
| 1.0 | Oct 2026 | First specification. Written from the implemented code: action catalogue, three response modes, **pending approvals** (Approve / Reject, who decided, expiry), **multi-step playbooks** with an editor, runs, **response rules** (automatic playbooks with test mode, cooldown and hourly limit), escalation and notification, safety rules, undo, configuration, API, and worked examples. |
