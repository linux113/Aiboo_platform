# TriGate v2 – Windows test guide

## Test status (PC "gorilla" / Anonmoyous, run of 1–2 Oct 2026)

| Test | Status | Result seen |
|---|---|---|
| Setup (auditpol) | ✅ Done | all 4 commands succeeded |
| 1 Password guessing | ✅ Done | risk 66 HIGH BLOCK (Trust 30 / Intent 80 / Impact 45) |
| 2 False alarm / Real threat | ✅ Done | risk dropped 66 → 56; "score HIGHER" message after Real threat |
| 3 New admin account (scores) | ✅ Done | risk 70 HIGH BLOCK, "created only 1 min ago", attack chain +15 |
| 3 **Run** button | 🔧 Fixed – re-test needed | failed on `Anonmoyous\aibootest2`; fixed (PC-name prefix removed, never locks your own account) |
| 4 Importance → Critical | ⏳ Pending | not done yet |
| 5 Suspicious service | ✅ Done | risk 56 HIGH, suspicious command +15, persistence +10 |
| 6 Send Event + blocklist IP | ✅ Done | risk 70 HIGH, blocklist +30 |
| 7 Restart keeps memory | ❓ Confirm | likely passed if the agent was restarted before the 12:15 AM log-cleared card |
| 8 Security log cleared | ✅ Done | risk 64 HIGH BLOCK, Intent 100, "covering tracks?" +10 |
| 9 Device trust (new) | ⏳ Pending | needs the new code – see section 9 |
| Clean up | ⏳ Pending | service deleted ✅; delete aibootest / 2 / 3; remove 45.95.147.3 from blocklist |

TriGate = 3 gates that **every** Windows event now goes through:

| Gate | Question | Score 0–100 | High score means |
|---|---|---|---|
| 1 Trust  | Who is it – can we trust them? | failed logons, remote vs local, internet IP, known user/IP (memory), new account, **device trust** (this PC's antivirus / firewall / updates / BitLocker / UAC, known vs unknown other computer) | **good** (trusted) |
| 2 Intent | Is it an attack? | attack pattern + MITRE, history 24 h–7 days, working hours (local time), IP blocklist / AbuseIPDB, your feedback | **bad** |
| 3 Impact | How bad would it be? | PC importance (Endpoints page), admin rights, evidence destroyed, persistence, working hours | **bad** |

**Final risk = 30% × (100 − Trust) + 40% × Intent + 30% × Impact**
≥ 75 CRITICAL / ≥ 55 HIGH → BLOCK · ≥ 35 MEDIUM → HOLD · below → PASS.
Actions only run automatically if `auto_response = true` in config.ini (default off) – otherwise you click **Run** on a recommendation.

Memory file: `agent\trigate_memory.json` (history 7 days, known logons, feedback, importance). Delete it (agent stopped) to reset learning.

Optional config.ini keys (all have defaults – you do **not** need to add them):
```ini
importance     = normal     ; low / normal / high / critical (dashboard setting overrides this)
business_hours = 8-20       ; working hours, local PC time
abuseipdb_key  =            ; free key from abuseipdb.com (only public IPs are checked)
```
Your own bad-IP list: `agent\config\ip_blocklist.txt` (one IP or range per line, re-read automatically).

---

## 0. Start everything (new code)

1. Stop the old agent, backend and frontend windows (Ctrl+C).
2. Download the new branch ZIP, extract, copy your old `backend\.env` and `agent\config.ini` into the new folders.
3. Backend: `cd backend` → `npm install` → `npm run dev`
4. Frontend: `cd frontend` → `npm install` → `npm run dev`
5. **Admin** Command Prompt → `cd agent` → `python main.py`
   The agent window must show a line like:
   `TriGate: importance NORMAL (config.ini default), working hours 8:00-20:00, threat intel: blocklist, memory ...\trigate_memory.json`
6. In the same Admin Command Prompt (a second one), turn on the Windows audit settings:
   ```
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"User Account Management" /success:enable
   auditpol /set /subcategory:"Security Group Management" /success:enable
   auditpol /set /subcategory:"Audit Policy Change" /success:enable
   ```
   (Turning on auditing may itself create an **"Audit policy changed"** TriGate card – that is correct.)
7. Dashboard → **Agent Console** → tab **TriGate (n)**. Keep it open.

Numbers below can differ by ±10: after 20:00 / before 08:00 Intent gets **+10 (outside working hours)**, during the day Impact gets **+5 (working hours)**.

## 1. Brute force → Trust low, Intent high

```
net user aibootest Test@12345 /add
```
→ one card **"New user account created"** (MEDIUM / HOLD, Intent ~50) – expected.

Now type a **wrong** password 5 times (run the command 5 times):
```
runas /user:aibootest cmd
```
Expected card: **"Password guessing (many failed logons)"**, MITRE T1110, **BLOCK / HIGH, risk ~64**
- Trust ~30 (red): `5 failed logons ... (-35)`, `local (+5)`, `'aibootest' has never logged in successfully (-10)`
- Intent ~70 (red): `Password guessing – MITRE T1110 (+70)`
- Impact ~50: `importance NORMAL (+35)`, `A real account is being targeted (+10)`
- Recommended: `Lock account 'aibootest'` (Run button), `Tell the security team`

The agent window also prints a `TRIGATE BLOCK [HIGH]` block with the same reasons.
A 6th, 7th wrong password each gives a new card (old 5-second de-dup no longer hides them).

## 2. Learning – "False alarm" lowers future scores

1. On the brute-force card click **👍 False alarm** → text "Saved on the agent – similar events will score LOWER". Agent window: `TriGate feedback 'false_alarm' for brute_force|aibootest`.
2. **Wait 5 minutes** (the brute-force counter resets), then 5 wrong passwords again with `runas /user:aibootest cmd`.
3. Expected new card: **HOLD / MEDIUM, risk ~53** (was ~64)
   - Trust ~40: `You marked this as a false alarm before (1x) (+10)`
   - Intent ~50: `You marked this as a false alarm 1x before (-25)`, `1 other alert(s) for 'aibootest' in the last 24 hours (+5)`
   - **🚨 Real threat** does the opposite (+10 Intent per click).

## 3. New account made administrator (attack chain)

```
net user aibootest2 Test@12345 /add
net localgroup administrators aibootest2 /add
```
Expected 2 cards. The second: **"User added to an admin group"**, MITRE T1098, **BLOCK / HIGH, risk ~66**
- Trust ~60: `'aibootest2' was created only 1 min ago (-20)`
- Intent ~95: `Brand-new account was made administrator (typical attack chain) (+15)`
- Impact ~55: `Affects administrator rights (+15)`
- Recommended: `Disable account 'aibootest2'` → click **Run** → OK. Agent disables the account; see the **Isolation & Termination** tab.
  (It acts on **aibootest2**, never on you – the admin who made the change.)
- Check it worked: `net user aibootest2` → `Account active  No`. Undo: `net user aibootest2 /active:yes`.
- Safety: Run will **refuse** to disable the account the agent runs as (you) or SYSTEM, and says why.

## 4. Importance → Impact changes

1. Dashboard → **Endpoints** page → your PC card → **Importance** dropdown → **Critical**.
   Text: "Saved – Impact now uses CRITICAL". Agent window: `importance of this PC set to CRITICAL`.
2. Create any event, e.g. `net user aibootest3 Test@12345 /add`.
3. Impact bar now ~45 points higher; first Impact reason: `This PC's importance is CRITICAL (set on the dashboard Endpoints page) (+80)`; risk goes up (MEDIUM → HIGH).
4. Set it back to **Normal**.

## 5. Suspicious service (persistence) – safe, never started

```
sc create AiBooTestSvc binPath= "cmd.exe /c powershell -enc AAAA" start= demand
```
Expected: **"New service installed"**, MITRE T1543.003 – Intent `Runs a suspicious command (+15)`, Impact `Can survive a reboot (persistence) (+10)`, recommended "Check service 'AiBooTestSvc'".
Remove: `sc delete AiBooTestSvc`

## 6. Threat intel blocklist (dashboard Send Event)

1. Open `agent\config\ip_blocklist.txt`, add a line `45.95.147.3`, save.
2. Agent Console → **Send Event** → type network_intrusion, severity high, Source IP `45.95.147.3` → Send.
3. Card (TEST badge): Trust `Came from an internet address (45.95.147.3) (-20)`, Intent `45.95.147.3 is on your blocklist (+30)`.

## 7. Memory survives restart

1. Ctrl+C the agent → last lines: `TriGate memory saved: N events (7 days), N known users, N feedback entries -> ...trigate_memory.json`
2. Start again (`python main.py`). Endpoints page still shows your importance; a new brute-force card still shows the false-alarm and 24-hour history reasons.

## 8. Optional: Security log cleared (deletes old Security events!)

```
wevtutil cl Security
```
Expected **"Security log cleared"**, MITRE T1070.001, Intent ~100, Impact `Removes evidence (+15)`. If no card appears, restart the agent once.

## 9. Device trust (Gate 1) – new

The agent now checks this PC's security health at start-up and every 15 minutes (read-only).
Exact rules: `TRIGATE_SPECIFICATION_v1.0.md` section 5.3.

1. Start the agent (as Administrator). Within about 1 minute the agent window shows one line:
   `Device health (Gate 1): McAfee ON, firewall ON, last update 6 d ago, BitLocker OFF, UAC ON`
   (your antivirus name / numbers will differ; items Windows cannot report are simply left out).
2. Create any event, e.g. `net user aibootest4 Test@12345 /add`.
   The Gate 1 box on the TriGate card now has a **Device:** line, for example
   `+5 Device: this PC is healthy (...)` or `-5 Device: system drive is not encrypted (BitLocker off)`.
3. Firewall test (Admin Command Prompt) – turn the Public profile off for a moment:
   ```
   netsh advfirewall set publicprofile state off
   ```
   Restart the agent (so it re-checks now instead of in 15 min). The window shows
   `Device health (Gate 1): ... firewall OFF (Public)`.
   Create an event (`net user aibootest5 Test@12345 /add`): Gate 1 shows
   `-10 Device: Windows Firewall is OFF (Public)` and Trust is 10–15 points lower than in step 2.
4. **Turn the firewall back on straight away:**
   ```
   netsh advfirewall set publicprofile state on
   ```
5. Optional: set `device_trust = false` in `config.ini` → no Device lines (turns the feature off).

Note: device health shifts every risk score a little (healthy PC: about −1 or −2 risk;
firewall off: about +3). So Test 1 may now show 65 instead of 66 – that is expected.

## 10. Clean up

```
net user aibootest /delete
net user aibootest2 /delete
net user aibootest3 /delete
net user aibootest4 /delete
net user aibootest5 /delete
sc delete AiBooTestSvc
```
- Remove `45.95.147.3` from `ip_blocklist.txt`.
- Set importance back to Normal.
- Old firewall rules from earlier tests: `netsh advfirewall firewall show rule name=all | findstr AiBoO` → delete each with `netsh advfirewall firewall delete rule name="<name>"`.
- Reset learning: stop agent, delete `agent\trigate_memory.json`.

---

# Part 2 – New dashboard features (Task 29)

What is new, in one line each:

| Feature | Where you see it |
|---|---|
| Alert management (acknowledge / assign / notes / close with reason / reopen) | new top tab **Alerts** (red number = alerts that need action) |
| Executive dashboard, charts, security trends, threat statistics, customisable widgets | new top tab **Executive** |
| Risk / Compliance / Executive reports as **PDF, CSV, JSON** | new top tab **Reports** (also buttons on Executive and Alerts) |
| Compliance checks (ISO 27001:2022 + NIST CSF 2.0) of each PC | **Reports** → "Compliance checks", **Executive** → Compliance widget |
| Event correlation (attack chains) | **Agent Console → Correlated**, Live Threat Feed, Alerts |
| Live Threat Feed shows TriGate HOLD / BLOCK | **Dashboard** → Live Threat Feed |
| Real threat-intel feeds (Feodo, Spamhaus DROP, ET compromised) + live connection check | **Executive** → Protection status |
| Behaviour analysis (learns each user's normal logins) | **Executive** → Protection status, alerts "Behaviour anomaly" |
| Dynamic access control: restrict account for N minutes (auto re-enable), throttle IP, lock screen | Dashboard playbooks, Agent Console → Dispatch, TriGate **Run** buttons |
| Freeze Badge (needs a badge-system webhook) | Dashboard playbooks |

Who can do what: **admin** and **analyst** can change alerts and run actions; **viewer** can only look (the buttons are hidden and the backend refuses).

New optional settings – you do **not** need to add them (defaults shown):

`agent\config.ini`
```ini
threat_feeds               = feodo, spamhaus_drop, et_compromised   ; or "off"
threat_feed_hours          = 24      ; re-download the feeds every 24 h
intel_connection_scan      = true    ; check live connections of this PC against the feeds
intel_scan_seconds         = 30
correlation_window_minutes = 60      ; events this close together can form an attack chain
behaviour_analytics        = true
behaviour_min_logons       = 20      ; learning needs 20 real logons ...
behaviour_min_days         = 3       ; ... over at least 3 days before it alerts
legacy_behaviour_alerts    = false   ; old UEBA / DNA cards (the unnamed "Security event" ones)
```

`backend\.env`
```ini
REPORT_TZ=Asia/Kolkata              ; time zone used in reports (the dashboard sends your browser's zone anyway)
BADGE_WEBHOOK_URL=                   ; only for Freeze Badge (see Test 16)
BADGE_WEBHOOK_TOKEN=                 ; optional secret sent as "Authorization: Bearer ..."
```

## 11. Start the new version

1. Stop agent, backend, frontend (Ctrl+C in each window).
2. Download the new ZIP, extract, copy your old `backend\.env` and `agent\config.ini` into the new folders.
3. Backend window: `cd backend` → `npm install` → `npm run dev`
   (new packages: `pdfkit` for PDF reports – `npm install` is required).
4. Frontend window: `cd frontend` → `npm install` → `npm run dev`
   (new package: `recharts` for the charts – `npm install` is required).
5. **Admin** Command Prompt → `cd agent` → `python main.py`. Look for these lines:
   - `Intelligence: threat feeds feodo, spamhaus_drop, et_compromised, behaviour analytics ON (learns after 20 logons / 3 days), incident correlation ON`
   - `Threat intelligence online - live connections checked every 30s ...`
6. Log in to the dashboard. At the top you now see **Dashboard · Executive · Alerts · Reports · …**

Optional check of the backend alone: `cd backend` → `npm test` → must end with `# pass 7` and `# fail 0`.

## 12. Alerts – acknowledge, assign, close

1. Make an alert: repeat **Test 1** (6 wrong passwords) or **Test 3** (new user).
2. Open the **Alerts** tab. The new alert is at the top (red number on the tab goes up).
   PASS decisions are **not** alerts; only HOLD / BLOCK, high/critical detections and attack chains.
3. Click the row → details on the right (PC, user, IP, Trust / Intent / Impact, recommended actions).
4. Click **👀 Acknowledge** → status becomes *acknowledged*, assignee becomes you.
5. Type a name in "Assign to" (e.g. `soc-team`) → **👤 Assign**.
6. Type a note → **📝 Add note**.
7. Choose **False alarm** in the list → **✅ Close**. Status becomes *closed (False alarm)*.
8. Click **↩ Reopen** → back to *open*. Close it again with **Resolved**.
9. "History" at the bottom must list: created → acknowledged → assigned → note → closed → reopened → closed.
10. Tick 2–3 rows on the left → blue bar → **Acknowledge** or **Close** them all at once.
11. **⬇ Export CSV** → open the file in Excel (one row per alert).

Restart the backend and reload: the alerts are still there (they are saved in MongoDB).
If the Alerts page says *"Database offline – alerts kept in memory"*, MongoDB is not running.

## 13. Executive dashboard, charts, widgets

1. Open **Executive**. You see: Key figures, Security posture (0–100), Security trend chart, Alerts by severity (donut), Alert handling, Top attack types, Most targeted users, Compliance, Protection status, Top attacking IPs, Latest serious alerts.
2. Switch **7 days / 30 days / 90 days** → numbers and charts change.
3. Posture score: starts at 100, minus points for open alerts and compliance gaps (the widget shows the exact sum). Close alerts in Test 12 → the score goes up (refresh after ~3 seconds).
4. "Mean time to acknowledge / resolve" fill in after Test 12.
5. **⚙ Customise** → untick a widget (it disappears), move one with ▲ ▼, switch "wide / half" → **Done**. Reload the page → your layout is kept (saved in this browser). "Reset to default" undoes it.

## 14. Reports – PDF and CSV

1. **Reports** tab → choose a period (e.g. Last 30 days).
2. **Executive Security Summary → ⬇ PDF**: opens/saves `aiboo-executive-report-<date>.pdf` with key figures, an alerts-per-day bar chart, top attacks, latest serious alerts and compliance gaps.
3. **Risk Report → ⬇ PDF** and **⬇ CSV** (CSV = every alert, highest risk first, opens in Excel).
4. **Compliance Report → ⬇ PDF**: score per PC, ISO / NIST controls met, every check and how to fix it.
5. Times in the reports use your browser's time zone (shown in the PDF header).

## 15. Compliance checks (ISO 27001 / NIST CSF)

1. The agent must run as **Admin**. Within about a minute of starting (then every 15 minutes) it checks this PC.
2. **Reports** → "Compliance checks" shows: score, pass / warning / fail counts, "ISO 27001:2022 controls met", "NIST CSF 2.0 controls met", and a table of 15 checks (antivirus, definitions, firewall, Windows updates, BitLocker, UAC, logon auditing, account lockout, password length, Guest account, SMBv1, Remote Desktop, monitoring agent, security log not cleared, incident handling).
3. Tick **only gaps** → only failed / warning checks, each with a 🔧 fix.
4. Try one fix and check that it changes: e.g. a warning/fail for **account lockout** → Admin Command Prompt:
   `net accounts /lockoutthreshold:10` → wait up to 15 minutes (or restart the agent) → the check turns **pass** and the score goes up.
   Undo afterwards if you want: `net accounts /lockoutthreshold:0`.

## 16. Playbooks – Restrict Account, Throttle Segment, Freeze Badge

**Restrict Account (temporary, real Windows change)**
1. Make a test user: `net user aibootest6 Test@12345 /add`
2. Dashboard → Response Orchestration → **Restrict Account** → user `aibootest6`, Minutes `2` → Confirm.
3. Check: `net user aibootest6` → "Account active  **No**".
4. Wait ~2–3 minutes → `net user aibootest6` → "Account active **Yes**" again (the agent re-enabled it by itself).
   (Your own account is always refused – you cannot lock yourself out.)

**Throttle Segment (real Windows QoS limit, no hardware needed)**
1. Dashboard → **Throttle Segment** → IP `1.1.1.1`, speed `64`, minutes `5` → Confirm.
2. Check in Admin PowerShell: `Get-NetQosPolicy -PolicyStore ActiveStore` → a policy `AiBoO-Throttle-1-1-1-1-32` with ThrottleRate 64000 (bits per second).
3. After 5 minutes it is gone. To remove it earlier: Agent Console → Dispatch → **Remove throttle** → `1.1.1.1`.

**Freeze Badge (needs a badge system)**
1. Without setup: click **Freeze Badge** → it says *"needs setup"*; Confirm gives *"No badge system connected…"*. That is correct.
2. To test the connection without a real badge system: open https://webhook.site in your browser, copy "Your unique URL".
3. Put it in `backend\.env`: `BADGE_WEBHOOK_URL=https://webhook.site/...` → restart the backend.
4. Dashboard → **Freeze Badge** → `EMP-1042` → Confirm → green message. On webhook.site you see the request with `"action":"freeze_badge","badge_id":"EMP-1042"`. Agent Console → Isolation & Termination shows "Badge Frozen".
5. For real use, your badge vendor (or Power Automate / n8n in front of it) gives you the URL.

## 17. Correlation, threat intel, behaviour

**Attack chain (correlation)**
1. Within 60 minutes, do **Test 1** (wrong passwords) and then **Test 3** (new user + Administrators).
2. Agent Console → **Correlated (1)** → "ATTACK CHAIN" with the stages, e.g. *Credential Access → Persistence → Privilege Escalation*, the user and IP.
3. The same incident appears in **Alerts** (type *Incident*) and on the Dashboard Live Threat Feed. If more events come, the same card grows (no duplicates).

**Threat-intel feeds + live connection check**
1. Executive → **Protection status** → green badges "Feodo Tracker (n) / Spamhaus DROP (n) / ET Compromised (n)" with the number of bad IPs downloaded (needs internet; files are kept in `agent\threat_feeds\`).
2. Live test with your own list: add the line `1.1.1.1` to `agent\config\ip_blocklist.txt`.
3. Admin PowerShell (keeps a connection open for 70 seconds):
   `$c = New-Object Net.Sockets.TcpClient('1.1.1.1', 443); Start-Sleep 70; $c.Close()`
4. Within ~30 seconds the agent window shows `THREAT INTEL MATCH: ...` with the program name (powershell.exe) and a TriGate card / alert appears.
5. Remove `1.1.1.1` from `ip_blocklist.txt` afterwards.

**Behaviour analysis**
- It learns from real Windows logons (event 4624) and only starts alerting after **20 logons over 3 days** per user, so it cannot be tested in one day. Protection status shows progress: "Behaviour: 0/1 users learned".
- After learning, a login at an unusual hour, from a new IP, or the first remote (RDP) login creates a "Behaviour anomaly" alert.
- The old unnamed "Security event" cards from UEBA / DNA are **gone** (they were noise).

## 18. Clean up (Part 2)

```
net user aibootest6 /delete
net accounts /lockoutthreshold:0      (only if you changed it in Test 15 and want it back)
```
- Remove `1.1.1.1` from `agent\config\ip_blocklist.txt`.
- Remove `BADGE_WEBHOOK_URL` from `backend\.env` if you used webhook.site.
