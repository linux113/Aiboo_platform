# TriGate v2 – Windows test guide

TriGate = 3 gates that **every** Windows event now goes through:

| Gate | Question | Score 0–100 | High score means |
|---|---|---|---|
| 1 Trust  | Who is it – can we trust them? | failed logons, remote vs local, internet IP, known user/IP (memory), new account | **good** (trusted) |
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

## 9. Clean up

```
net user aibootest /delete
net user aibootest2 /delete
net user aibootest3 /delete
sc delete AiBooTestSvc
```
- Remove `45.95.147.3` from `ip_blocklist.txt`.
- Set importance back to Normal.
- Old firewall rules from earlier tests: `netsh advfirewall firewall show rule name=all | findstr AiBoO` → delete each with `netsh advfirewall firewall delete rule name="<name>"`.
- Reset learning: stop agent, delete `agent\trigate_memory.json`.
