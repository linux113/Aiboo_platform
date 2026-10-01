# TriGate Adaptive Decision Framework – Specification v1.0

**Xenthives.AI Technologies · AiBoO platform · Companion document referenced in the AiBoO Project Proposal (sections 7.4, 9.6 and Appendix E)**

| | |
|---|---|
| Version | 1.0 |
| Status | Implemented – this document describes the code exactly as shipped |
| Code | `agent/gates/` (Python agent) · dashboard card `frontend/src/components/TriGateCard.tsx` |
| Tests | `agent/tests/test_trigate.py`, `agent/tests/test_device_trust.py`, `agent/tests/test_lock_user_account.py` |
| Field test guide | `TRIGATE_TEST_GUIDE.md` |

> Rule for this document: **every number here is the number in the code.** If you change a weight or a factor in `agent/gates/`, change it here too (and the unit tests will tell you which examples moved).

---

## 1. Purpose and scope

The proposal says the TriGate *"evaluates every security event through three complementary dimensions – Trust, Intent and Impact – and combines them into a context-aware, explainable security recommendation"*. This specification defines:

1. the **architecture** (where the gates sit, what flows between them),
2. the **context model** (what is known about an event before scoring),
3. the **decision logic** of each gate (every factor and its points),
4. the **mathematical framework** (how three scores become one risk and one verdict),
5. **learning and memory** (how analyst feedback and history change future scores),
6. **design philosophy, safety rules and configuration**,
7. **worked examples** taken from real test runs on a Windows PC.

Out of scope for v1.0: physical-security inputs (CCTV, badges) and organisation-wide policy engines – see §14.

---

## 2. Design philosophy

| Principle (from the proposal) | How v1.0 implements it |
|---|---|
| Context over alerts | Every event is turned into a *context* (who, from where, on which device, when, history) before any score is given. |
| Explainable AI | A score is **only** the sum of listed factors. Each factor = points + one plain-English sentence, shown on the dashboard. No hidden model. |
| Every event is evaluated | Gate 1 never drops events (the old 5-second de-duplication that hid brute force was removed). Only a true duplicate of the same Windows record is skipped. |
| Human in the loop | TriGate **recommends**. Nothing destructive runs unless an analyst clicks **Run** (with a confirm) or the owner sets `auto_response = true`. |
| Adaptive / learning | "False alarm" / "Real threat" clicks and 7-day history are stored on disk and change later scores. |
| Privacy by design | Only metadata already in Windows logs is used. AbuseIPDB (optional) receives public IPs only. Device health checks are read-only. |
| Never punish twice for unknowns | Missing data gives **0 points**, not a penalty (e.g. BitLocker on Windows Home, no device health on Linux). The single exception is "could not tell which user did this" (−15), because an anonymous actor is itself a trust problem. |

---

## 3. Architecture

### 3.1 Position in AiBoO

```
Windows Event Log ─┐
Agent engines ─────┤  ThreatEvent      ┌─────────┐ GateDecision ┌─────────┐ GateDecision ┌─────────┐ final GateDecision
Dashboard test ────┼─────────────────► │ Gate 1  │ ───────────► │ Gate 2  │ ───────────► │ Gate 3  │ ──► dashboard card
Remote log sender ─┘   (event bus)     │ TRUST   │              │ INTENT  │              │ IMPACT  │ ──► memory (history)
                                       └─────────┘              └─────────┘              │ + RISK  │ ──► response engine
                                                                                         └─────────┘     (only if auto_response
                                                                                                          or analyst clicks Run)
```

This matches the proposal's six-layer architecture: AiCore (ingestion / normalisation / context) → **Layer 4 Decision = TriGate** → Layer 5 Adaptive Response (PseudoLock / response engine) → Layer 6 Presentation (dashboard).

### 3.2 Components

| File | Responsibility |
|---|---|
| `gates/trigate_patterns.py` | Classifies an event into an attack **pattern** (with MITRE ATT&CK id and base intent), IP kind, local time, settings, local-account name clean-up. Pure functions. |
| `gates/gate1_perimeter.py` | Builds the **context** and computes **Trust** (Gate 1), including device trust. |
| `gates/device_posture.py` | Reads this PC's security health (antivirus, firewall, updates, BitLocker, UAC) in a background thread. |
| `gates/gate2_behavioural.py` | Computes **Intent** (Gate 2). |
| `gates/threat_intel_lookup.py` | IP reputation: local blocklist file + optional AbuseIPDB. |
| `gates/gate3_adaptive.py` | Computes **Impact** (Gate 3), the **final risk**, verdict and recommended actions. |
| `gates/trigate_memory.py` | Long-term memory on disk (`trigate_memory.json`): history, known users / IPs / devices, feedback, importance. |
| `gates/gate_response_bridge.py` | Prints the final decision in the agent window. Executes nothing. |
| `core/orchestrator.py` | Wires the gates, reads `config.ini`, handles dashboard commands (importance, feedback). |

### 3.3 Data contract

Each gate publishes a `GateDecision` whose `metadata["trigate"]` grows:

```json
{
  "context":  { "...see §4..." },
  "trust":    { "score": 30, "level": "untrusted",  "factors": [{"points": -35, "text": "..."}] },
  "intent":   { "score": 80, "level": "malicious",  "factors": [...], "mitre": {"id": "T1110", "name": "Brute Force"} },
  "impact":   { "score": 45, "level": "moderate",   "factors": [...], "importance": "normal" },
  "risk":     { "score": 66, "level": "high", "weights": {"trust": 0.3, "intent": 0.4, "impact": 0.3} },
  "recommended": [{ "action": "revoke_identity", "target": "aibootest", "text": "Lock account 'aibootest' ..." }],
  "pattern": "brute_force", "entity": "aibootest", "subject": "aibootest"
}
```

All values are JSON-safe; the dashboard renders this object directly.

---

## 4. Context model (built once, in Gate 1)

| Field | Meaning | Source |
|---|---|---|
| `pattern`, `pattern_label`, `mitre_id`, `mitre_name` | Attack pattern (§6.1) | Windows event id, else threat type |
| `entity` | **Who did it** (for logons: the user; for admin changes: the admin) | `user_id` / `actor` |
| `subject` | **Who / what it was done to** (target account) | `target_user`, else user, else entity |
| `src_ip`, `ip_kind` | Source address and kind: `public` / `private` / `local` / `none` | event |
| `logon_type`, `logon_kind` | Windows logon type and simplified kind: `local` / `remote` / `clear_text` / `runas` | event 4624/4625/4648 |
| `workstation` | Name of the computer a logon came from | event 4624/4625 |
| `computer`, `on_this_pc` | Computer that recorded the event; whether that is the PC running the agent | event / hostname |
| `failure_reason`, `failed_attempts` | Why a logon failed; burst count | parser / brute-force detector |
| `service_name`, `task_name`, `command` | For services / tasks / processes | event |
| `local_time`, `local_hour`, `local_minute` | Time **in the PC's own time zone** (not UTC) | event timestamp |
| `test_event`, `test_intent` | Dashboard "Send Event" tests (severity → base intent) | payload |

Name normalisation: Windows writes local accounts as `THISPC\alice`; the prefix is removed when it is this PC, `.` or `BUILTIN` (domain accounts like `CORP\alice` are kept). If the only "user" is the PC's own name (e.g. service installs), the entity is treated as **unknown**.

---

## 5. Gate 1 – TRUST ("who is it – can we trust them?")

**Start value: 70** (neutral). Score = clamp(70 + Σ factor points, 0, 100). **High = good.**

### 5.1 Identity and authentication confidence

| Condition | Points | Text on the card |
|---|---|---|
| No user could be identified | −15 | Could not tell which user did this |
| Brute force (≥ 5 failed logons in 5 min) | −35 | *n* failed logons in a few minutes (password guessing) |
| Single failed logon | −10 | Failed logon (*reason*) |
| User name does not exist | −10 | Tried a user name that does not exist (guessing names) |
| Account locked out | −15 | The account got locked out |
| Password sent in clear text | −25 | Password sent in clear text over the network |
| Remote logon (network / RDP) | −15 | Remote logon (*type*) |
| RunAs / explicit credentials | −5 | '*A*' used the password of '*B*' (RunAs) |
| Local keyboard logon | +5 | Logon at this PC's own keyboard (local) |

### 5.2 Access legitimacy (where from, known before?)

| Condition | Points | Text |
|---|---|---|
| Internet (public) IP | −20 | Came from an internet address (*ip*) |
| Other PC on the LAN | −5 | Came from another PC on the network (*ip*) |
| User has logged in successfully on this PC before (memory) | +10 | '*user*' normally logs in on this PC |
| Logon-type event and user never logged in successfully | −10 | '*user*' has never logged in successfully on this PC |
| Known user, IP seen before for that user | +10 | '*user*' has logged in from *ip* before |
| Known user, new IP | −10 | First time '*user*' is seen from *ip* |
| Target account created ≤ 24 h ago (group changes) | −20 | '*account*' was created only *N* ago |
| User gave rights to their own account | −15 | The user gave rights to their own account |

### 5.3 Device trust

Device trust has two parts.

**(a) The other computer** – only when the event names a workstation that is *not* this PC:

| Condition | Points | Text |
|---|---|---|
| Workstation has been used for a successful logon here before (memory) | +5 | Device '*X*' has logged in here successfully before |
| Workstation never seen in a successful logon | −10 | Device '*X*' has never logged in here before (unknown computer) |

**(b) This PC's security health** – only for events recorded on the PC running the agent (`on_this_pc`). Collected by `device_posture.py` with one read-only PowerShell call at start-up and every `device_check_minutes` (default 15):

| Check | Data source | Condition | Points |
|---|---|---|---|
| Antivirus real-time protection | Windows Security Center (`root/SecurityCenter2 AntiVirusProduct`, bit `0x1000`), fallback `Get-MpComputerStatus` | none on | −15 |
| Antivirus definitions | Security Center bit `0x10`, or Defender signature age > 7 days | out of date | −5 |
| Windows Firewall | `Get-NetFirewallProfile` | any profile off | −10 |
| Windows updates | newest `Get-HotFix`, fallback Windows Update last install | > 60 days / 31–60 days | −10 / −5 |
| Disk encryption | `Get-BitLockerVolume` (system drive) | protection off | −5 |
| User Account Control | registry `EnableLUA` | off | −5 |
| **All known checks pass** (at least 2 known) | – | healthy | **+5** |

Rules: unknown checks give 0 points; the total device-health penalty is **capped at −30** (reasons are kept, points are scaled) so one weak PC does not make every event "untrusted". Third-party antivirus (McAfee, Norton, …) is recognised through Security Center, so a passive Defender is not reported as "no antivirus".

### 5.4 Learning

| Condition | Points | Text |
|---|---|---|
| Analyst marked this pattern for this user as False alarm *k* times | +10·*k* (max +20) | You marked this as a false alarm before (*k*x) |

### 5.5 Levels and per-gate verdict

trusted ≥ 70 · uncertain 40–69 · untrusted < 40. Gate verdict: PASS ≥ 70, HOLD ≥ 40, else BLOCK (informational – the final verdict comes from §8).

---

## 6. Gate 2 – INTENT ("is it an attack?")

Score = clamp(Σ factor points, 0, 100). There is no start value: the **base intent of the pattern** is the first factor. **High = bad.**

### 6.1 Attack patterns (base intent, MITRE ATT&CK, impact flags)

Windows event ids map first (4625/4771/4776 failed logon, ≥ 5 in 5 min = brute force; 4740 lockout; 1102 log cleared; 4719 audit policy; 4728/4732/4756 group add – admin if the group is privileged; 4720 account created; 4726 deleted; 4697/7045 service; 4698 task; 4648 RunAs; 4672 admin logon; 4688 process; 5140/5145 share; 5156–5158 firewall). Otherwise the event's threat type is used.

| Key | Label | Base intent | MITRE ATT&CK | Impact flags |
|---|---|---|---|---|
| brute_force | Password guessing (many failed logons) | 70 | T1110 Brute Force | – |
| failed_logon | Failed logon | 30 | T1110 Brute Force | – |
| account_lockout | Account locked out | 55 | T1110 Brute Force | – |
| log_cleared | Security log cleared | 90 | T1070.001 Indicator Removal: Clear Windows Event Logs | evidence |
| audit_policy_changed | Audit policy changed | 75 | T1562.002 Impair Defenses: Disable Windows Event Logging | evidence |
| admin_group_add | User added to an admin group | 75 | T1098 Account Manipulation | admin rights |
| group_add | User added to a normal group | 20 | T1098 Account Manipulation | – |
| account_created | New user account created | 50 | T1136.001 Create Account: Local Account | – |
| account_deleted | User account deleted | 40 | T1531 Account Access Removal | – |
| service_installed | New service installed | 55 | T1543.003 Windows Service | persistence |
| scheduled_task | Scheduled task created | 45 | T1053.005 Scheduled Task | persistence |
| explicit_credentials | Logon with someone else's password (RunAs) | 35 | T1078 Valid Accounts | – |
| admin_logon | Administrator privileges used at logon | 15 | T1078 Valid Accounts | admin rights |
| process_started | Process started | 20 | T1059 Command and Scripting Interpreter | – |
| network_share | Network share accessed | 25 | T1021.002 Remote Services: SMB | – |
| firewall_event | Firewall connection event | 20 | – | – |
| network_intrusion | Network intrusion | 55 | T1046 Network Service Discovery | – |
| identity_mismatch | Identity problem | 40 | T1078 Valid Accounts | – |
| insider_threat | Insider activity | 45 | – | – |
| malware | Malware | 80 | T1204 User Execution | – |
| phishing | Phishing | 60 | T1566 Phishing | – |
| anomalous_behavior / behavioral_anomaly | Unusual behaviour | 40 | – | – |
| physical_intrusion | Physical intrusion | 50 | – | – |
| access_request | Access request check | 20 | – | – |
| device_health_fail | Device health check failed | 40 | – | – |
| zero_trust_violation | Zero Trust policy violation | 50 | – | – |
| geo_velocity / ghost_login | Login from an impossible location | 60 | T1078 Valid Accounts | – |
| threat_intel_alert | Matches a known-bad indicator (threat intel) | 65 | – | – |
| physical_cyber_mismatch | Badge / login location mismatch | 50 | T1078 Valid Accounts | – |
| correlated_attack | Several alerts linked together (possible attack chain) | 65 | – | – |
| memory_threat | Malicious code found in memory | 75 | T1055 Process Injection | – |
| insider_threat_converged | Insider pattern over several days | 55 | – | – |
| tailgating | Tailgating (badge and camera do not match) | 45 | – | – |
| ransomware_prelude | Ransomware warning signs | 80 | T1486 Data Encrypted for Impact | – |
| logon_success | Successful logon | 10 | T1078 Valid Accounts | – |
| privilege_use | Sensitive privilege used | 30 | T1078 Valid Accounts | – |
| generic | Security event | 30 | – | – |

Dashboard test events use the chosen severity as base intent: low 25, medium 45, high 65, critical 80.

### 6.2 Other intent factors

| Condition | Points | Text |
|---|---|---|
| Brute force with ≥ 20 attempts | +10 | Very many attempts (*n*) |
| Service / task / process runs a suspicious command (powershell, cmd /c, mshta, rundll32, certutil, `-enc`, URLs, Temp/AppData/Public folders, …) | +15 | Runs a suspicious command: … |
| …program is in Windows\System32 or Program Files | −10 | Program is in a normal Windows / Program Files folder |
| *d* other alerts for the same user in 24 h | +5·*d* (max +20) | *d* other alert(s) for '*user*' in the last 24 hours |
| ≥ 3 more alerts in the rest of the 7 days | +10 | *w* alerts for '*user*' in the last 7 days |
| **Attack chain:** account made admin ≤ 24 h after it was created | +15 | Brand-new account was made administrator (typical attack chain) |
| **Covering tracks:** evidence pattern after other alerts today | +10 | Happened after *n* other alert(s) today (covering tracks?) |
| Outside working hours (local time, default 8–20) | +10 | Happened at HH:MM, outside working hours |
| Source IP on your blocklist (`config/ip_blocklist.txt`, IPs or CIDR) | +30 | *ip* is on your blocklist |
| AbuseIPDB confidence ≥ 25 (optional key) | +25 | AbuseIPDB … |
| AbuseIPDB confidence 0 | −5 | … (clean) |
| Ingestor anomaly score ≥ 0.8 (unusual event rate) | +5 | Unusually many events of this type right now |
| Analyst False alarm *k* times (same pattern + user) | −25·*k* (max −60) | You marked this as a false alarm *k*x before |
| Analyst Real threat *k* times | +10·*k* (max +20) | You confirmed this as a real threat *k*x before |

Levels: malicious ≥ 70 · suspicious 40–69 · probably harmless < 40.

---

## 7. Gate 3 – IMPACT ("how bad would it be?")

Score = clamp(Σ factor points, 0, 100). **High = bad.**

| Condition | Points | Text |
|---|---|---|
| PC importance (dashboard Endpoints page, else `config.ini importance`) | low 10 · normal 35 · high 60 · critical 80 | This PC's importance is *X* |
| Pattern touches administrator rights | +15 | Affects administrator rights |
| Pattern destroys evidence / blinds monitoring | +15 | Removes evidence / blinds security monitoring |
| Pattern survives reboot | +10 | Can survive a reboot (persistence) |
| Failed logon / brute force on an existing account | +10 | A real account is being targeted ('*x*') |
| …on a non-existent account | −5 | The account does not exist (nothing to take over) |
| Account locked out | +10 | '*x*' is locked out and cannot work |
| Account deleted | +10 | Account '*x*' was removed |
| Built-in Administrator involved | +10 | The built-in Administrator account is involved |
| During working hours | +5 | During working hours (people are using this PC) |

Levels: severe ≥ 70 · moderate 40–69 · limited < 40.

---

## 8. Mathematical framework

### 8.1 Gate scores

For gate *g* with factors *f₁…fₙ* (each an integer number of points):

```
Trust  T = clamp( 70 + Σ fᵢ , 0, 100 )
Intent I = clamp(      Σ fᵢ , 0, 100 )
Impact P = clamp(      Σ fᵢ , 0, 100 )
clamp(x, 0, 100) = min(100, max(0, round(x)))
```

### 8.2 Final risk

Trust is "good-is-high", so it is inverted into *distrust* before weighting:

```
Risk R = round( 0.30 · (100 − T)  +  0.40 · I  +  0.30 · P )        0 ≤ R ≤ 100
```

Weights: **Intent 40 %** (is it an attack is the strongest signal), **Distrust 30 %**, **Impact 30 %**. `round` is Python's round-half-to-even (66.5 → 66).

### 8.3 Risk levels and verdicts

| Risk | Level | Verdict | Meaning |
|---|---|---|---|
| ≥ 75 | CRITICAL | BLOCK | Act now; isolation is also recommended for evidence / persistence / admin / malware patterns |
| 55–74 | HIGH | BLOCK | Act; recommended actions offered with a Run button |
| 35–54 | MEDIUM | HOLD | Analyst should review |
| < 35 | LOW | PASS | Logged for history only |

"BLOCK" executes automatically **only** when `auto_response = true`; by default it is a recommendation.

### 8.4 Confidence

```
Gate 1 / Gate 2 confidence = min(0.95, 0.55 + 0.05 · number_of_factors)
Final confidence           = min(0.95, 0.50 + 0.03 · total_factors_of_all_three_gates)
```

More independent evidence → higher confidence, never above 95 %.

### 8.5 Sensitivity (what one factor is worth in final risk)

| 10 points in… | changes Risk by |
|---|---|
| Trust | 3 (opposite sign) |
| Intent | 4 |
| Impact | 3 |

Example: a healthy-device bonus (+5 Trust) lowers risk by 1.5; firewall off (−10 Trust) raises it by 3.

---

## 9. Decision logic – recommended actions

Generated by `recommend(ctx, level)`; the dashboard shows a **Run** button for executable ones.

| Pattern | Recommendation | Action id |
|---|---|---|
| any, level LOW | No action needed – logged | `log` |
| brute force / failed logon / lockout / network intrusion with an IP | Block IP in Windows Firewall | `block_access` |
| brute force / failed logon / lockout on an existing account | Lock account until the owner confirms (not your own account!) | `revoke_identity` |
| admin group add / account created | Disable the **new / changed** account (never the admin who made the change) | `revoke_identity` |
| log cleared / audit policy changed | Ask the user why | manual |
| service installed / scheduled task | Check and remove if unknown | manual |
| CRITICAL + evidence / persistence / admin / malware pattern | Isolate this PC while you investigate | `isolate_asset` |
| always (non-LOW) | Tell the security team / PC owner | `notify_security` |

### Safety rules in the response engine

* `revoke_identity` strips `THISPC\` / `.\` from names; refuses domain accounts with a clear message (must be done on the domain controller).
* It **refuses to disable the account the agent runs as** (you would lock yourself out) and built-in system accounts.
* It verifies with `net user` afterwards and reports **Failed** if Windows still shows the account active.
* Process kills use a never-kill list; firewall rules are named `AiBoO_*` so they can be found and removed.

---

## 10. Learning and memory

Stored in `trigate_memory.json` next to `config.ini`, saved at most once a minute and on shutdown (atomic write; a corrupt file is renamed `.bad` and a fresh one started).

| Memory | Kept | Used by |
|---|---|---|
| events (who, pattern, risk, subject) | 7 days, max 5000 | Gate 2 history, attack chains, Gate 1 "created only N ago" |
| logons (user → IPs, logon types) | max 2000 users, 50 IPs each | Gate 1 known user / known IP |
| devices (workstation → users) | max 500 | Gate 1 device trust (a) |
| feedback (pattern + user → false_alarm / confirmed counts) | permanent | Gate 1 (+10/FA) and Gate 2 (−25/FA, +10/confirmed) |
| importance | permanent | Gate 3 |

Learning effect of one "False alarm" click on the same pattern + user: Trust +10 and Intent −25 → risk −13. Two clicks: Trust +20, Intent −50 → risk −26. Real-threat clicks: Intent +10 each (max +20).

---

## 11. Configuration (`agent/config.ini`, all optional)

| Key | Default | Effect |
|---|---|---|
| `importance` | normal | Default PC importance (Gate 3); dashboard setting overrides it |
| `business_hours` | 8-20 | Working hours, local time (Gate 2 off-hours, Gate 3 working hours) |
| `abuseipdb_key` | – | Enables AbuseIPDB lookups (public IPs only, cached 6 h, 3 s timeout) |
| `device_trust` | true | Include this PC's health in Gate 1 |
| `device_check_minutes` | 15 | How often device health is re-read |
| `auto_response` | false | Run BLOCK actions automatically (otherwise only via the dashboard) |
| `remote_commands` | true | Allow dashboard Run / Dispatch |

Blocklist: `agent/config/ip_blocklist.txt` (one IP or CIDR per line, re-read automatically when saved).

---

## 12. Explainability and presentation

The dashboard TriGate card shows: risk badge (score, level, verdict), pattern label + Windows event id + MITRE id, the event description, the formula line, three bars (Trust / Intent / Impact) each with its factor list (+/− points and text), recommended actions with Run buttons, and the **False alarm / Real threat** buttons. The agent window prints the same decision as a coloured block.

---

## 13. Worked examples (real test run, PC "Anonmoyous", 1–2 Oct 2026, importance NORMAL, off-hours)

**A. Password guessing – 5 wrong passwords for `aibootest` at 23:06**

| Gate | Factors | Score |
|---|---|---|
| Trust | 70 − 35 (5 failed logons) + 5 (local keyboard) − 10 (never logged in) | **30** |
| Intent | 70 (brute force, T1110) + 10 (23:06 off-hours) | **80** |
| Impact | 35 (normal) + 10 (real account targeted) | **45** |
| Risk | 0.3·70 + 0.4·80 + 0.3·45 = 21 + 32 + 13.5 = 66.5 → **66 HIGH, BLOCK** | |

**B. `aibootest2` added to Administrators 1 minute after it was created (23:35)**

| Gate | Factors | Score |
|---|---|---|
| Trust | 70 − 20 (created only 1 min ago) | **50** |
| Intent | 75 (admin group, T1098) + 10 (2 other alerts for lalit) + 15 (attack chain) + 10 (off-hours) = 110 → | **100** |
| Impact | 35 + 15 (admin rights) | **50** |
| Risk | 0.3·50 + 0.4·100 + 0.3·50 = 15 + 40 + 15 = **70 HIGH, BLOCK** | |

**C. Security log cleared by `lalit` (00:15)**

| Gate | Factors | Score |
|---|---|---|
| Trust | 70 (known user, nothing negative) | **70** |
| Intent | 90 (log cleared, T1070.001) + 20 (6 alerts / 24 h, capped) + 10 (after 13 alerts – covering tracks) + 10 (off-hours) → | **100** |
| Impact | 35 + 15 (removes evidence) | **50** |
| Risk | 9 + 40 + 15 = **64 HIGH, BLOCK** | |

**D. Same as A, with device trust (v1.0 device checks)**

* Healthy PC (antivirus on, firewall on, updated): Trust 30 + 5 = 35 → Risk 19.5 + 32 + 13.5 = 65 → **65 HIGH**.
* Firewall off on the Public profile: Trust 30 − 10 = 20 → Risk 24 + 32 + 13.5 = 69.5 → **70 HIGH**.

---

## 14. Limitations and roadmap (v1.x → v2)

| Item | Status in v1.0 | Planned |
|---|---|---|
| Physical context in Trust / Impact (badge, CCTV) | not used | v2 – when surveillance correlation is production-ready |
| Device health of *other* computers | only "known / unknown" | receive posture from each agent and look it up by workstation name |
| Organisation policies (per-department rules, approvals) | config.ini + importance only | policy engine in the admin module |
| Weights | fixed 30 / 40 / 30 | per-organisation tuning, learned from feedback statistics |
| Correlation into incidents | history + two chains (new admin, covering tracks) | full incident correlation (AiCore) |
| Learning | counts per pattern + user | decay over time; per-IP and per-device feedback |

---

## 15. Verification

* Unit tests: `cd agent && python -m pytest tests` (all TriGate rules, device trust, memory persistence, safety rules).
* Field test: `TRIGATE_TEST_GUIDE.md` (8 tests on a real Windows PC with expected scores).

## 16. Version history

| Version | Date | Change |
|---|---|---|
| 1.0 | Oct 2026 | First specification, written from the implemented TriGate v2 code: Trust / Intent / Impact, memory and learning, threat intel, **device trust** (this PC's health + known devices), safety rules, worked examples from the Windows field test. |
