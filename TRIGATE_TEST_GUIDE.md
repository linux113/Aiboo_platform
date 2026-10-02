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
legacy_correlation         = false   ; old "[CORRELATED] Identity compromise ..." cards (replaced by ATTACK CHAIN)
```

Optional Windows environment variable (not in config.ini):
`AIBOO_QUEUE_MAX_AGE_HOURS=24` – unsent alerts older than this are thrown away instead of being sent late.

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

## 19. Fixes from the 2 Oct 2026 test

What you saw → why → what changed:

| You saw | Real cause | Fix |
|---|---|---|
| ~28 "identity mismatch (ZeroTrustAgent / IdentityAgent)" and "insider threat" alerts right after start, posture 37–38 | The file `agent\alerts_queue.db` was stored in GitHub with 120 old unsent items from 12 Sept (PC "Sejal"). Every fresh ZIP re-sent them, and the backend gave each one a new id and today's date | File removed from GitHub and ignored. The agent now throws away queued items older than 24 h or tried 5 times. The backend keeps the agent's own id and time, so a re-sent item can never become a second alert |
| "[CORRELATED] Identity compromise with lateral movement", source "unknown", 19 days ago | Same old file + the old correlation engine | Old engine off (`legacy_correlation = false`). ATTACK CHAIN replaces it |
| "identity mismatch (ZeroTrustAgent)" risk 75 next to TriGate "Password guessing" | A finding made from a Windows event was turned into a second alert | Findings made from Windows events no longer become alerts; TriGate's alert is the one to handle (the finding still shows in the live feed) |
| "Malicious process detected: powershell.exe" 85% | AiBoO's own Gate 1 device check runs `powershell -EncodedCommand ...` and the scanner flagged it | Processes started by the agent itself are skipped. Encoded PowerShell started by anyone else is still reported |
| Excel shows `01-Jan` for endpoints | "1 / 1" looks like a date to Excel | Two rows: `Endpoints online` and `Endpoints known` |
| Empty space beside "Security posture" | A wide widget came straight after a half one | Half-width widgets are paired, and the grid fills gaps by itself (also in a custom order) |

**Remove the old junk alerts that are already in your database** (once):
1. Stop the backend window (Ctrl+C).
2. In the `backend` folder:
   ```
   npm run clear-alerts -- --old-noise --dry-run
   npm run clear-alerts -- --old-noise
   ```
   The first line only counts. The second deletes only the junk (identity mismatch / insider threat findings, Windows-event copies and "[CORRELATED]" cards). TriGate alerts and ATTACK CHAIN incidents are kept.
   To start completely fresh instead: `npm run clear-alerts -- --all`.
3. Start the backend again (`npm run dev`).

**If you re-use an old folder:** delete `agent\alerts_queue.db` before starting the agent (the new agent would drop the old items anyway).

**Excel tip:** `########` in the Date column only means the column is too narrow – double-click the line between column headers A and B.

## 20. PseudoLock – Pending approvals and multi-step playbooks (new)

Full description: `PSEUDOLOCK_SPECIFICATION_v1.0.md`. Nothing new to install (no new packages).

**Before you start**
1. Download the new ZIP and unzip it. Copy your old `backend\.env` and `agent\config.ini` into the new folders (the ZIP does not contain them).
2. Start the backend (`npm run dev` in `backend`), the frontend (`npm run dev` in `frontend`) and the agent (**Run as Administrator**), the same way as before.
3. In `agent\config.ini`, `auto_response` must be `false` (or not there at all). That is the default. With `true` the agent acts by itself and no approvals are created.
4. Open the dashboard. There is a new tab **Response** next to **Alerts**.

### 20.1 Safe test – nothing changes on the PC (do this first)
1. **Response** → **📘 Playbooks** → the card **"Safe test (changes nothing on the PC)"** → **▶ Run**.
2. In the window: PC = your PC name (it is filled in if only one agent is online) → **▶ Start**.
3. The screen jumps to **▶ Runs**. You see the steps:
   - ✅ Notify;
   - ◔ Wait 5 s;
   - then ⏳ "Wait for approval".

   The bell shows "Test playbook started on <PC>".
4. The **Response** tab now has an amber number **1**. Click **✋ Approvals**. You see a card "Test approval – press Approve or Reject …" with a **countdown** (about 10:00) and the time it expires.
5. Type a note, e.g. `testing`, and press **✔ Approve**.
6. **▶ Runs** → the run is **Done**, every step ✅, and step 3 says "Approved by <your email>". The bell shows "Test playbook finished".
7. Run it again, and this time press **✖ Reject**. The run becomes **Stopped**, and the last step is *Skipped*.
8. **✋ Approvals** → **History**: both entries show **Approved by / Rejected by** your email, the time and your note.

### 20.2 TriGate asks for approval (real attack test)
1. Admin Command Prompt: `net user aibootest7 Test@12345 /add`
2. Do **Test 1** with the user `aibootest7`: run `runas /user:aibootest7 cmd` and type a **wrong** password, **exactly 5 times**. (More can make Windows lock the account by itself – see the warning at the start of §21.)
3. Within about 30 seconds:
   - the bell shows **"Approval needed – Disable account 'aibootest7' for 30 min …"**;
   - the **Response** tab gets an amber number.

   (A local test like `runas` has no IP, so there is no "Block IP" approval. An attack from another PC over the network also gives a "Block IP" approval.)
4. **Response → ✋ Approvals**. Check that the card shows:
   - **TriGate BLOCK**;
   - **risk** (about 60–70);
   - Action: *Disable account for N minutes → aibootest7 · 30 min*;
   - your PC;
   - the countdown (30:00).
5. Make more wrong passwords. The **same** card now says **seen ×2**, and the timer starts again. No second card appears.
6. Press **✔ Approve**. The card shows "Sent to … waiting", then **✅ Done on the PC: Account 'aibootest7' disabled for 30 min …**.
7. Check in the Command Prompt: `net user aibootest7` → "Account active **No**".
8. Turn it back on early: Agent Console → Dispatch → **Lift restriction** → `aibootest7`. Otherwise it is turned back on by itself after 30 minutes.
9. **Reject test:** repeat steps 2–4 and press **✖ Reject**. `net user aibootest7` stays "Account active **Yes**".

**Expiry test (optional):**
1. Put `APPROVAL_EXPIRY_MINUTES=2` in `backend\.env` and restart the backend.
2. Repeat step 2 and do **not** click anything.
3. After 2 minutes the card moves to **History** as **Expired** ("Nobody decided within 2 min").
4. Remove the line from `backend\.env` afterwards and restart the backend.

### 20.3 Run a playbook from an alert
1. **Alerts** → click the "Password guessing – aibootest7" alert → button **▶ Run playbook**.
2. The window shows:
   - **For alert:** …;
   - playbook **"Contain password guessing"** is chosen already;
   - PC and User name (`aibootest7`) are filled in.
3. IP address: if it is empty (local `runas` test), type the test IP `45.95.147.3` → **▶ Start**.
4. The screen jumps to **Response → ▶ Runs**:
   - ✅ Block IP 45.95.147.3;
   - ✅ Disable account aibootest7 (30 min);
   - ✅ Notify.

   The bell shows "Blocked 45.95.147.3 and disabled account aibootest7 for 30 min on <PC>".
5. Check:
   - Windows Defender Firewall → Inbound Rules → a rule `AiBoO_Block_45_95_147_3_…`;
   - `net user aibootest7` → Active **No**.

### 20.4 Make your own playbook with the editor
1. **Response → 📘 Playbooks → ＋ New playbook**.
2. Name: `My test playbook`.
3. Step 1 is already there (Action, Block IP). Change **Action** to *Disable account for N minutes*. Target becomes `{user}`. Minutes = `2`.
4. Click **＋ ✋ Wait for approval**, then **＋ 📣 Notify dashboards**. Change the message to `Done for {user} on {pc}`.
5. Use **↑** on the approval step so that it is step 1 (approval first, then the account, then the message).
6. Press **💾 Save playbook**. If something is missing, a red list tells you exactly what. The card shows **CUSTOM v1**.
7. **▶ Run** → PC = yours, User name = `aibootest7` → Start → **Approvals** → **Approve**. The account is disabled for 2 minutes, and **Runs** shows all ✅.
8. **✎ Edit** → untick **Enabled** → Save. **▶ Run** is now greyed out. **🗑 Delete** removes it.
9. Built-in playbooks have no Edit or Delete: use **⧉ Copy & edit**.

### 20.5 What a viewer sees (optional)
Log in as a user with the **viewer** role. They can open **Response** and see everything, but there are **no** Approve, Reject, Run or Edit buttons. The message says only admin or analyst can approve.

### 20.6 Clean up
```
net user aibootest7 /delete
```
Remove the test firewall rule in **Admin PowerShell**:
```
Remove-NetFirewallRule -DisplayName "AiBoO_Block_45_95_147_3*"
```

## 21. PseudoLock – Response rules: playbooks that start by themselves (new)

A **rule** says: *WHEN this kind of attack happens → THEN run this playbook* (automatically, after one click, or only a message). Full description: `PSEUDOLOCK_SPECIFICATION_v1.0.md` §7.7. Nothing new to install.

**Test status (PC "gorilla", 2 Oct 2026):** 21.1–21.6 ✅ passed (test mode, automatic run "Ran playbook" + account disabled 2 min, cooldown). 21.7 approval card ✅ and Reject ✅; **Approve & start** still to be pressed once.

**Before you start**
- Do the setup of §20 first: new ZIP, copy your old `backend\.env` and `agent\config.ini`, start the backend, the frontend and the agent (**Run as Administrator**).
- The test user `aibootest7` from §20.2 must exist. If you deleted it, run this again in an Admin Command Prompt: `net user aibootest7 Test@12345 /add`
- Open the dashboard → **Response** → there is a new tab **⚙ Rules**.

> ⚠ **Important:** a rule acts on **every** matching attack, also on real users. Keep the test rule limited to **your PC** (step 21.2) and **delete it at the end** (step 21.8).

> ⚠ **Windows locks the account by itself after too many wrong passwords** (usually 10 within 10 minutes). Then `runas` says *"1909: The referenced account is currently locked out"*, `net user aibootest7` says **Account active: Locked**, and TriGate reports **"Account locked out"** instead of **"Password guessing"**. To avoid this:
> - type **exactly 5** wrong passwords per round (5 are enough for "Password guessing");
> - wait **10 minutes** between two rounds;
> - see your Windows limits with `net accounts` ("Lockout threshold", "Lockout duration");
> - if the account is **Locked**: `net user aibootest7 /active:yes` (Admin Command Prompt) or wait 10 minutes.
>
> Before **every** round, `net user aibootest7` must say **Account active: Yes**.

### 21.1 Make a small test playbook (only needs the user name)
A local `runas` test has **no IP address**. The built-in "Contain password guessing" needs an IP, so with `runas` the rule would only say *Skipped*. So we make a playbook that only needs the user:
1. **Response → 📘 Playbooks → ＋ New playbook**.
2. Name: `Rule test - disable user 2 min`
3. Step 1: **Action** = *Disable account for N minutes*, Target = `{user}`, Minutes = `2`.
4. Click **＋ 📣 Notify dashboards**, message: `Rule disabled {user} on {pc} for 2 min`
5. **💾 Save playbook**.

### 21.2 Make the rule – in TEST MODE first (nothing happens on the PC)
1. **Response → ⚙ Rules → ＋ New rule**.
2. Name: `Test rule - password guessing`
3. **WHEN** part:
   - Attack type: **Password guessing (many failed logons)** is already ticked. Also tick **Account locked out**, so the rule works even if Windows locks the account during the test.
   - Risk at least: `55`. TriGate verdict: **BLOCK** ticked, HOLD not ticked.
   - Only these PCs: click the grey button **+ <your PC name>** under the box (or type your PC name exactly as on the Dashboard).
   - Where the attack comes from: **Any (or no IP)**. Time of day: **Any time**.
4. **THEN** part: click **⚡ Run automatically**. Playbook: **Rule test - disable user 2 min**.
   - A yellow box says this playbook needs the **user name**. That is correct.
5. **🧪 Test mode** is ticked (it is ticked for every new rule). Leave it ticked.
6. **💾 Save rule**. The list now shows a card **#1 Test rule - password guessing** with **⚡ Run automatically**, **🧪 test mode** and **ON**.

### 21.3 "Test against old alerts"
1. On the card, click **🔍 Test against old alerts**.
2. You see: *"Last 30 days: this rule would have matched N of M TriGate alerts"* and a small table.
   - If you did Test 1 or §20.2 before, N is 1 or more, and the table shows the "Password guessing – aibootest7" alerts.
   - N = 0 is also fine if you never did a password test on this PC.
   - Below the table: "Not matched because: other attack type (…)". This shows why the other alerts would not start the rule.

### 21.4 Attack in test mode
1. In a normal Command Prompt: `runas /user:aibootest7 cmd` and type a **wrong** password, **exactly 5 times**.
2. Within about 30 seconds, go to **⚙ Rules** and press **⟳ Refresh**. In **📜 Activity** you see:
   **🧪 Test mode - nothing done** · rule Test rule - password guessing · *"TEST MODE - would have: run "Rule test - disable user 2 min". Matched: Password guessing on <PC> (risk …, user aibootest7)"*
   If one round of wrong passwords gives TriGate more than one BLOCK, you also see **⏸ Cooldown - already handled** lines just above it. That is normal: one round is handled once.
3. Check: `net user aibootest7` → "Account active **Yes**". Nothing was changed.
4. **✋ Approvals** still shows the normal TriGate card "Disable account 'aibootest7' for 30 min". In test mode the rule does not hide it. Press **✖ Reject** on it.

### 21.5 Switch test mode OFF – the rule now acts by itself
1. On the rule card: **✎ Edit** → untick **🧪 Test mode**. A yellow warning appears: *"This rule will change PCs without asking anyone."* → **💾 Save rule**. The card no longer shows "test mode".
2. Check `net user aibootest7` says **Yes**, and wait **10 minutes** after the last wrong-password round. Then type a wrong password for `aibootest7` **exactly 5 times** again.
3. Within about 30 seconds:
   - The bell shows **"Rule disabled aibootest7 on <PC> for 2 min"**.
   - **⚙ Rules → ⟳ Refresh → Activity**: **▶ Ran playbook** · *"Started "Rule test - disable user 2 min" automatically …"*. Click **see run**.
   - **▶ Runs**: the run has the purple badge **⚙ automatic (rule)** and *"started by Rule "Test rule - password guessing""*. All steps are ✅.
   - **✋ Approvals**: **no** new card. The rule took care of it, so you are not asked twice.
4. Check: `net user aibootest7` → "Account active **No**". After 2 minutes it shows **Yes** again by itself.
5. The rule card now shows **"matched 2× · last …"** (one test match and one real match).

### 21.6 Cooldown – the same attack is not handled twice
1. Wait until `net user aibootest7` shows **Active Yes** again. Also wait 10 minutes after the last round.
2. Type a wrong password **exactly 5 times** again (within 30 minutes of step 21.5).
3. **Activity** shows **⏸ Cooldown - already handled** · *"Already handled N min ago (cooldown 30 min)"*. The account stays **Active Yes**, and no approval appears.

### 21.7 "Ask first" – the playbook starts only after you click
1. **✎ Edit** → **✋ Ask first** → **💾 Save rule**. Saving also starts the cooldown fresh.
2. Wait 10 minutes (`net user aibootest7` = **Yes**), then type a wrong password **exactly 5 times** again.
3. The bell shows **"Approval needed – Rule "Test rule - password guessing" wants to run "Rule test - disable user 2 min" on <PC> (user aibootest7)"**.
4. **✋ Approvals**: the card has the grey label **Response rule**, the text *"Starts playbook Rule test - disable user 2 min when approved"*, and a countdown.
5. Press **✔ Approve & start**. In **History** the card says **✅ Playbook "Rule test - disable user 2 min" started**.
6. **▶ Runs** shows *"started by Rule "Test rule - password guessing" (approved by <your email>)"*, and `net user aibootest7` → Active **No** (back to Yes after 2 minutes).
7. *(Optional)* Repeat once more after 10 minutes and press **✖ Reject**: no run is started, and the account stays Active Yes.

**Optional – other things on the Rules screen:**
- **…or start from an example**: 4 ready rules (password guessing from the internet, known-bad IP, new admin at night, security log cleared). They open in the editor in test mode. Save one, use **↑ ↓** to change the order, then delete it.
- **Switch off**: the card turns grey and shows **OFF**. An OFF rule is never checked, so the normal approvals come back.
- A playbook that a rule uses cannot be deleted. The message says which rule uses it.
- A user with the **viewer** role sees the rules and the Activity, but has no New, Edit, Switch or Delete buttons.

### 21.8 Clean up (important)
1. **⚙ Rules** → on **Test rule - password guessing** press **🗑** → OK.
2. **📘 Playbooks** → **Rule test - disable user 2 min** → **🗑 Delete**. This only works after the rule is deleted.
3. If you no longer need the test user: `net user aibootest7 /delete`
