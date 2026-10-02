# AiBoO – FULL PILOT TEST on a second PC (PC2 on a different network)

Every test in this document says:
- **WHERE**: which PC and which window
- **DO**: exactly what to type or click
- **WHAT HAPPENS**: what AiBoO does behind the scenes
- **YOU WILL SEE**: what appears on the screen
- **PASS ✅**: how you know it worked

After each test, tick its box in the **Result sheet** at the end (Part 10). If a test fails, write down the **test number**, take a screenshot, and continue with the next test.

---

## The two PCs

| Name in this document | What it is | What you do there |
|---|---|---|
| **MAIN PC** | your PC `gorilla` | Backend, dashboard and ngrok run here. You **watch** and **click Approve** here |
| **PC2** | the other PC, on a different network | The AiBoO agent runs here. You **attack** here |

```
PC2: you attack ──> AiBoO agent on PC2 sees it ──> internet (ngrok) ──> MAIN PC dashboard shows it
                                                                              │
PC2: account disabled / IP blocked  <──────── internet (ngrok) <──── you click APPROVE
```

**Example values used in this document. Always type YOUR real values:**

| What | Example in this document | Yours (write it here) |
|---|---|---|
| ngrok address | `https://abcd-1234.ngrok-free.dev` | ______________________ |
| PC2 name | `DESKTOP-7KQ2M` | ______________________ |
| Your own Windows user on PC2 | `pc2user` | ______________________ |

**Test users created on PC2 during the test:**
- `aibootest8`: the password-attack victim
- `aibootest9`: the "secret admin"
- `aibootest10`, `aibootest11`, `aibootest12`: small extra tests

**Time needed:** about 4 hours. Password attacks need a **10-minute wait** between rounds, or Windows locks the account. The order below already puts other tests into those waits. The ⏰ sign shows where the 10-minute clock starts.

**Windows on PC2:**
- **WINDOW A** = Admin Command Prompt where the agent runs. **Never type or click in it.**
- **WINDOW B** = second Admin Command Prompt. **All attacks are typed here.**
- **WINDOW C** = Admin PowerShell, for checks.

To open an Admin window: Start menu → type `cmd` (or `powershell`) → **right-click → Run as administrator** → Yes.

---

# PART 1 – SETUP OF THE MAIN PC (gorilla)

### S1 – Start the backend
- **WHERE:** MAIN PC, new Command Prompt
- **DO:** go to your AiBoO folder, then:
  ```
  cd backend
  npm run dev
  ```
- **YOU WILL SEE:** the text ends with a line saying the server runs on port **4000**. Leave this window open.

### S2 – Start the dashboard
- **WHERE:** MAIN PC, second Command Prompt
- **DO:**
  ```
  cd frontend
  npm run dev
  ```
  Then open Chrome at `http://localhost:3000` and log in.
- **YOU WILL SEE:** the AiBoO dashboard.

### S3 – Start the MAIN PC agent (recommended)
- **DO:** Admin cmd → `cd agent` → `python main.py`
- **WHY:** then the dashboard has 2 PCs (gorilla + PC2), and you can check that each attack is shown on the **right** PC.

### S4 – Switch off old test rules
- **WHERE:** dashboard → **Response** → **⚙ Rules**
- **DO:** switch every rule **OFF**.
- **WHY:** an old rule would react before you can test the normal approvals. You'll make a new rule in Part 6.

### S5 – (Optional) start with an empty alert list
- **DO:** stop the backend (Ctrl+C in the S1 window), then:
  ```
  npm run clear-alerts -- --all
  npm run dev
  ```
- **WHY:** only PC2's new results are in the list, so they're easy to find.

### S6 – Start ngrok
- **WHERE:** MAIN PC, third Command Prompt
- **DO:** if you have a fixed ngrok address (dashboard.ngrok.com → **Domains**), run:
  ```
  ngrok http --url=abcd-1234.ngrok-free.dev 4000
  ```
  If you don't have one, run:
  ```
  ngrok http 4000
  ```
- **YOU WILL SEE:** `Forwarding   https://abcd-1234.ngrok-free.dev -> http://localhost:4000`
- **Write the `https://...` address in the table at the top.**
- ⚠ This window must stay open for the whole test. Without a fixed address, the address changes every time ngrok restarts, and then you must change PC2's config again (step P6).

### S7 – Stop the MAIN PC from sleeping
Settings → System → Power → Screen and sleep → **Never**, just for today.

---

# PART 2 – SETUP OF PC2

### P1 – Install Python
python.org → Downloads → **Download Python 3.12** → run it → **tick "Add python.exe to PATH"** → Install Now.

### P2 – Get the agent
1. In Chrome on PC2, open:
   `https://github.com/linux113/Aiboo_platform/archive/refs/heads/arena/01a0e300-aiboo-platform.zip`
2. Unzip it. Copy the folder **`agent`** to **`C:\AiBoO\agent`**.

### P3 – Check that PC2 can reach the MAIN PC
- **DO:** in Chrome on PC2, open `https://abcd-1234.ngrok-free.dev/health` (your address + `/health`).
- **YOU WILL SEE:** a blue ngrok page → click **Visit Site** → `{"status":"ok", ...}`
- **PASS ✅** if you see `"status":"ok"`.
- ❌ If not, S1 (backend) or S6 (ngrok) isn't running on the MAIN PC.

### P4 – Install the agent's libraries (open WINDOW A = Admin cmd)
```
cd C:\AiBoO\agent
python -m pip install -r requirements.txt
```
- **YOU WILL SEE:** 1–3 minutes of text, ending with `Successfully installed ...`

### P5 – Find PC2's name
Type `hostname`. Example result: `DESKTOP-7KQ2M`. Write it in the table at the top.

### P6 – Write the config file
Type `notepad C:\AiBoO\agent\config.ini`. Delete everything and paste this. **Change the 2 lines marked ⬅**:
```
[AIBOO]
remote_url = https://abcd-1234.ngrok-free.dev
api_key = dev-key-change-in-production
server_ip = 127.0.0.1
log_level = INFO
endpoint_name = DESKTOP-7KQ2M
```
- `remote_url` ⬅ your ngrok address. Nothing after it: no `/` and no `/health`.
- `endpoint_name` ⬅ PC2's name. ⚠ **NEVER `gorilla`.** The ZIP still contains `gorilla`; if you leave it, the 2 PCs get mixed up.
- `api_key`: if the MAIN PC's `backend\.env` has a line `AGENT_API_KEY=xxx`, put that `xxx` here. Otherwise keep it as shown.

Save (Ctrl+S) and close.

### P7 – Turn on Windows security logging (still WINDOW A)
Type these 5 lines one by one. Each must answer `The command was successfully executed.`
```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```
**WHY:** without this, Windows doesn't write down wrong passwords, new users or new tasks, so AiBoO cannot see them.

### P8 – Look at PC2's lockout limit
Type `net accounts` and look at the line **Lockout threshold**. Usually it is `10`. Write it down: ______
**WHY:** more wrong passwords than this number locks the account. That's why each password attack below uses **exactly 5**.

### P9 – Stop the window freezing
Right-click the title bar of WINDOW A → **Properties** → untick **QuickEdit Mode** → OK.

### P10 – Start the agent
```
cd C:\AiBoO\agent
python main.py
```
- **YOU WILL SEE**, within about 1 minute:
  - `Loaded config from C:\AiBoO\agent\config.ini (backend=https://abcd-1234.ngrok-free.dev)`
  - `Command channel CONNECTED to https://abcd-1234.ngrok-free.dev/agent-channel as endpoint 'DESKTOP-7KQ2M' - remote actions from the dashboard are now enabled`
  - `Device health (Gate 1): <your antivirus> ON, firewall ON, last update ... , BitLocker ..., UAC ON`
- **PASS ✅** if you see **Command channel CONNECTED**.
- ❌ If you see `connect error`, the `api_key` or `remote_url` in P6 is wrong. Fix it, press Ctrl+C, and start again.

From now on, **don't touch WINDOW A**. Open **WINDOW B** (Admin cmd) and **WINDOW C** (Admin PowerShell).

---

# PART 3 – IS PC2 ACTIVE?

### T1 – PC2 is online on the dashboard
- **WHERE:** MAIN PC → **Endpoints**
- **YOU WILL SEE:**
  - At the top: **2 online** (1 if the gorilla agent isn't running).
  - A card **DESKTOP-7KQ2M** with a green **Online · <time>**.
- **PASS ✅** if the PC2 card is green.

### T2 – PC2 is in the agent list
- **WHERE:** MAIN PC → **Agent Console** → tab **Isolation & Termination**
- **YOU WILL SEE:** the PC list contains **DESKTOP-7KQ2M** (and gorilla).
- **PASS ✅** if PC2 is in the list.

### T3 – PC2 obeys the dashboard (first remote action)
- **DO:** Agent Console → **Isolation & Termination** → PC: **DESKTOP-7KQ2M** → Action: **Lock screen (user must sign in again)** → Target: `pc2user` → **Dispatch**
- **WHAT HAPPENS:** the dashboard sends the command over the internet to PC2, and the agent locks the screen.
- **YOU WILL SEE:**
  - PC2's screen locks. Sign in again.
  - The dashboard shows `✅ Done on DESKTOP-7KQ2M ...`
- **PASS ✅** if PC2's screen locked.

### T4 – PC2's security health (compliance)
- **WHERE:** MAIN PC → **Reports** → **Compliance checks** → choose **DESKTOP-7KQ2M** in the list
- **YOU WILL SEE:** PC2's score, pass/warning/fail counts, and 15 checks (antivirus, firewall, updates, BitLocker, UAC, Guest account, SMBv1, ...).
- **PASS ✅** if PC2 has its own results. If it isn't listed yet, wait 2 minutes and reload.

---

# PART 4 – ATTACKS ON PC2 (TriGate detects, PseudoLock responds)

**Where to look after every attack:** MAIN PC → **Agent Console** → tab **TriGate**. The newest card is at the top. Every card must say **DESKTOP-7KQ2M**, not gorilla.

A TriGate card has 3 boxes:
- **Gate 1 Trust**: who is it, can we trust them? (low = bad)
- **Gate 2 Intent**: does it look like an attack? (high = bad)
- **Gate 3 Impact**: how much damage could it do? (high = bad)

At the top: the **risk** number and the verdict:
- **BLOCK** (red): dangerous. AiBoO asks you for approval to act.
- **HOLD** (amber): suspicious. Watch it.
- **PASS**: harmless.

Approvals appear in MAIN PC → **Response** → **✋ Approvals**. The Response tab shows an amber number, and the bell 🔔 says "Approval needed".

Numbers can differ by ±10 from this document (time of day, PC health). That's normal.

---

### T5 – ATTACK: hacker changes the logging settings ("Audit policy changed")
- **WHAT IT IS:** hackers change Windows logging so their actions aren't recorded. You already did this in step P7.
- **YOU WILL SEE:** a card **"Audit policy changed"** for DESKTOP-7KQ2M. Recommendation: *Ask '...' why logs / audit settings were changed*.
- **PASS ✅** if the card is there. If not, type one P7 line again in WINDOW B and wait 30 seconds.

### T6 – ATTACK: hacker creates a new user
- **DO (WINDOW B):**
  ```
  net user aibootest8 Test@12345 /add
  ```
- **WHAT HAPPENS:** Windows writes event 4720 ("user created"). The agent sees it and TriGate scores it.
- **YOU WILL SEE:** card **"New user account created"**, **MEDIUM / HOLD**. There's no approval, because HOLD only warns.
- **PASS ✅** if the card says HOLD and DESKTOP-7KQ2M.

### T7 – ATTACK: password guessing, then PseudoLock **APPROVE** ⏰
- **DO (WINDOW B):**
  ```
  runas /user:aibootest8 cmd
  ```
  At `Enter the password for aibootest8:`, type `abc` and press Enter.
  It answers `RUNAS ERROR: ... The user name or password is incorrect.`
  👉 **Do this exactly 5 times.** ⏰ The 10-minute clock starts now.
- **WHAT HAPPENS:** 5 wrong passwords in a row means password guessing. TriGate says **BLOCK**. Because automatic actions are off, PseudoLock **asks you first**.
- **YOU WILL SEE:**
  1. TriGate card **"Password guessing (many failed logons)"**, MITRE T1110, **HIGH / BLOCK**, risk about 60–70.
     - Gate 1: `5 failed logons ... (-35)`
     - Gate 2: `Password guessing – MITRE T1110 (+70)`
  2. Bell: **"Approval needed – Disable account 'aibootest8' for 30 min ..."**
  3. **Response → ✋ Approvals**: a card with **TriGate BLOCK**, the risk, *Disable account for N minutes → aibootest8 · 30 min*, **DESKTOP-7KQ2M**, and a countdown (30:00).
- **DO:** on that approval card, type the note `pilot test` → **✔ Approve**.
- **WHAT HAPPENS:** the backend sends the order to PC2, and the agent disables the account.
- **YOU WILL SEE:**
  - The card says "Sent to … waiting", then **✅ Done on the PC: Account 'aibootest8' disabled for 30 min ...**
  - On PC2, WINDOW B: `net user aibootest8` shows **Account active   No**
- **UNDO:** Agent Console → **Isolation & Termination** → PC: DESKTOP-7KQ2M → **Lift account restriction now** → `aibootest8` → Dispatch.
  Then `net user aibootest8` shows **Account active   Yes**.
- **PASS ✅** if the account became **No** after Approve and **Yes** after Lift.

### T8 – ATTACK: hacker makes a "secret admin", then PseudoLock approve
- **DO (WINDOW B):**
  ```
  net user aibootest9 Test@12345 /add
  net localgroup administrators aibootest9 /add
  ```
- **WHAT HAPPENS:** a brand-new account becomes administrator within a minute. That's a typical attack chain.
- **YOU WILL SEE:**
  1. Card "New user account created" (aibootest9).
  2. Card **"User added to an admin group"**, MITRE T1098, **HIGH / BLOCK**:
     - Gate 1: `'aibootest9' was created only 1 min ago (-20)`
     - Gate 2: `Brand-new account was made administrator (typical attack chain) (+15)`
     - Gate 3: `Affects administrator rights (+15)`
  3. Approval: **"Disable account 'aibootest9' until someone confirms it is legitimate"**
- **DO:** **✔ Approve**.
- **YOU WILL SEE:** ✅ Done. `net user aibootest9` shows **Account active   No**. This one does **not** come back by itself.
- **UNDO:** `net user aibootest9 /active:yes`
- **PASS ✅** if the account was disabled. It must never disable `pc2user` (you).

### T9 – Attack chain (correlation)
- **WHERE:** MAIN PC → **Agent Console** → tab **Correlated**
- **YOU WILL SEE:** an **ATTACK CHAIN** card for DESKTOP-7KQ2M with stages such as *Credential Access → Persistence → Privilege Escalation*. The same incident is also in **Alerts** and in the Dashboard **Live Threat Feed**.
- **PASS ✅** if an attack chain for PC2 is shown. It links T7 and T8 because they happened within 60 minutes.

### T10 – PC importance makes the risk higher
- **DO:**
  1. MAIN PC → **Endpoints** → PC2 card → **Importance** → **Critical**.
     - The dashboard says "Saved – Impact now uses CRITICAL".
     - PC2 WINDOW A shows `importance of this PC set to CRITICAL`.
  2. WINDOW B: `net user aibootest10 Test@12345 /add`
- **YOU WILL SEE:**
  - The new "New user account created" card has a much bigger **Impact** than in T6.
  - The first Impact reason is `This PC's importance is CRITICAL (set on the dashboard Endpoints page) (+80)`.
  - The risk is higher: HOLD may become BLOCK.
- **DO:** set PC2's importance back to **Normal**.
- **PASS ✅** if the risk went up because of "CRITICAL".

### T11 – ATTACK: hacker installs a hidden program as a service
- **DO (WINDOW B):**
  ```
  sc create AiBooTestSvc binPath= "cmd.exe /c powershell -enc AAAA" start= demand
  ```
  This is safe: the service is never started.
- **YOU WILL SEE:** card **"New service installed"**, MITRE T1543.003:
  - Intent: `Runs a suspicious command (+15)`
  - Impact: `Can survive a reboot (persistence) (+10)`
  - Recommended: "Check service 'AiBooTestSvc' ..."
- **UNDO:** `sc delete AiBooTestSvc`
- **PASS ✅** if the card is there.

### T12 – ATTACK: hacker creates a scheduled task
- **DO (WINDOW B):**
  ```
  schtasks /create /tn AiBooTestTask /tr "powershell -enc AAAA" /sc once /st 23:59 /f
  ```
- **YOU WILL SEE:** card **"Scheduled task created"** with the recommendation "Check scheduled task 'AiBooTestTask' (taskschd.msc) and delete it if unknown".
- **UNDO:** `schtasks /delete /tn AiBooTestTask /f`
- **PASS ✅** if the card is there. If it's missing, check that the 5th line of P7 was done.

### T13 – ATTACK: password guessing again, then PseudoLock **REJECT** ⏰
⚠ Only start when **10 minutes** have passed since T7, and `net user aibootest8` says **Active Yes**.
- **DO (WINDOW B):** `runas /user:aibootest8 cmd` with a wrong password, **exactly 5 times**. ⏰ The clock starts again.
- **YOU WILL SEE:** a new "Password guessing" card and a new approval "Disable account 'aibootest8' ...".
- **DO:** **✖ Reject**.
- **YOU WILL SEE:**
  - The approval moves to **History** as **Rejected by <your email>**.
  - `net user aibootest8` still shows **Active Yes**. Nothing was changed.
- **DO (learning):** on this TriGate card, click **👍 False alarm**.
  - Text: "Saved on the agent – similar events will score LOWER".
  - PC2 WINDOW A: `TriGate feedback 'false_alarm' ...`
- **PASS ✅** if Reject changed nothing and the false alarm was saved.

### T14 – ATTACK: hacker from the internet with a known-bad IP, then PseudoLock block
A real internet hacker can't reach PC2 (its router protects it), so the dashboard **pretends** one. The **firewall block on PC2 is real**.
- **DO:**
  1. WINDOW B: `notepad C:\AiBoO\agent\config\ip_blocklist.txt` → add a new line `45.95.147.3` → save and close.
     (This is your own "bad IP list".)
  2. MAIN PC → **Agent Console** → tab **Send Event**:
     - PC: **DESKTOP-7KQ2M**
     - Event Type: **network intrusion**
     - Severity: **critical**
     - Source IP: `45.95.147.3`
     - Message: `pilot internet attack`
  3. Click **Send Test Event**.
- **WHAT HAPPENS:** the event goes to PC2's agent. TriGate sees an internet IP that is on the bad list.
- **YOU WILL SEE:**
  - `✅ DESKTOP-7KQ2M accepted the event`
  - A TriGate card with a **TEST** badge:
    - Gate 1: `Came from an internet address (45.95.147.3) (-20)`
    - Gate 2: `45.95.147.3 is on your blocklist (+30)`
  - Approval: **"Block IP 45.95.147.3 in Windows Firewall"**
- **DO:** **✔ Approve**. (If there's no approval because the verdict was HOLD, do it by hand: Agent Console → Isolation & Termination → PC2 → **Block IP (inbound)** → `45.95.147.3` → Dispatch.)
- **CHECK (WINDOW C):**
  ```
  Get-NetFirewallRule -DisplayName "AiBoO_Block_*" | Format-Table DisplayName,Direction,Action,Enabled
  ```
  You will see `AiBoO_Block_45_95_147_3_...   Inbound   Block   True`.
- **PASS ✅** if the firewall rule exists on PC2, and PC2 is still **Online** on the dashboard.

### T15 – ATTACK: a program on PC2 talks to a bad IP (real connection)
- **DO:**
  1. Open `ip_blocklist.txt` again → add a line `1.1.1.1` → save.
  2. WINDOW C (keeps a real connection open for 70 seconds):
     ```
     $c = New-Object Net.Sockets.TcpClient('1.1.1.1', 443); Start-Sleep 70; $c.Close()
     ```
- **WHAT HAPPENS:** every 30 seconds the agent checks PC2's live connections against the bad lists. It finds powershell talking to 1.1.1.1.
- **YOU WILL SEE:**
  - PC2 WINDOW A: `THREAT INTEL MATCH: ...` with `powershell.exe` and its PID.
  - TriGate card **"Matches a known-bad indicator (threat intel)"**. Recommendations:
    - Block IP 1.1.1.1
    - Stop powershell.exe (PID nnnn)
    - Slow down traffic
  - Approval: **"Block IP 1.1.1.1 ..."**
- **DO:**
  1. On the card, click **Run** next to **"Stop powershell.exe (PID ...)"** → OK.
     WINDOW C closes (the program was stopped). ✅ Open a new WINDOW C.
  2. On the approval "Block IP 1.1.1.1", click **✖ Reject**. (1.1.1.1 is a real, harmless DNS server.)
- **UNDO:** remove the line `1.1.1.1` from `ip_blocklist.txt`.
- **PASS ✅** if the match was found and the program was stopped from the dashboard.

### T16 – PC2's health changes the score (device trust)
- **DO (WINDOW B):**
  1. Turn the firewall off for a moment:
     ```
     netsh advfirewall set publicprofile state off
     ```
  2. Restart the agent: click WINDOW A → **Ctrl+C** → wait for it to stop → `python main.py`.
     - While stopping, you will see: `TriGate memory saved: N events ... -> ...trigate_memory.json`
     - While starting: `TriGate memory loaded: ...` and `Device health (Gate 1): ... firewall OFF (Public)`
  3. WINDOW B: `net user aibootest11 Test@12345 /add`
- **YOU WILL SEE:** in the new card's Gate 1 box: `-10 Device: Windows Firewall is OFF (Public)`. Trust is lower than in T6.
- **DO, straight away:**
  ```
  netsh advfirewall set publicprofile state on
  ```
  Restart the agent again (Ctrl+C → `python main.py`) → `firewall ON`.
- **PASS ✅** if "Firewall is OFF" lowered Trust. This also checks that **memory survives a restart**.

### T17 – Learning: "False alarm" lowers the score ⏰
⚠ Wait **10 minutes** after T13. `net user aibootest8` must be **Active Yes**.
- **DO (WINDOW B):** `runas /user:aibootest8 cmd` with a wrong password, **exactly 5 times**.
- **YOU WILL SEE:** a new "Password guessing" card with a **lower** risk than in T7/T13. You may see HOLD instead of BLOCK, and these reasons:
  - Trust: `You marked this as a false alarm before (1x) (+10)`
  - Intent: `You marked this as a false alarm 1x before (-25)`
- **DO:** click **🚨 Real threat** on this card. Future scores go up again (Intent +10 per click).
- **PASS ✅** if the score went down after "False alarm".

### T18 – ATTACK: Windows locks the account ("Account locked out") (optional)
Do this right after T17. Skip it if P8 showed lockout threshold **Never**.
- **DO (WINDOW B):** run `runas /user:aibootest8 cmd` with a wrong password **6 more times**. You'll pass the limit from P8.
  - At the end runas says: `1909: The referenced account is currently locked out`.
- **YOU WILL SEE:** card **"Account locked out"** (MITRE T1110). If an approval appears, **Reject** it.
- **UNDO:** `net user aibootest8 /active:yes`. If it's still locked, wait 10 minutes.
- **PASS ✅** if the "Account locked out" card is there.

### T19 – ATTACK: hacker deletes the evidence ("Security log cleared") (optional)
⚠ This deletes PC2's old Security log. Only do it on a test PC.
- **DO (WINDOW B):** `wevtutil cl Security`
- **YOU WILL SEE:** card **"Security log cleared"**, MITRE T1070.001, Intent about 100, Impact `Removes evidence (+15)`.
- **PASS ✅** if the card is there. If not, restart the agent once.

---

# PART 5 – PSEUDOLOCK TOOLS ON PC2 (playbooks and one-click actions)

### T20 – Safe test playbook: APPROVE (changes nothing on PC2)
- **DO:** MAIN PC → **Response** → **📘 Playbooks** → card **"Safe test (changes nothing on the PC)"** → **▶ Run** → PC: **DESKTOP-7KQ2M** → **▶ Start**.
- **WHAT HAPPENS:** a playbook is a list of steps that run one after the other: message → 5-second wait → approval → message.
- **YOU WILL SEE:**
  - The screen jumps to **▶ Runs**: ✅ Notify, ◔ Wait 5 s, then ⏳ "Wait for approval".
  - **✋ Approvals**: the card "Test approval – press Approve or Reject …" with a countdown.
- **DO:** **✔ Approve**.
- **YOU WILL SEE:** **▶ Runs** shows the run as **Done** with every step ✅, and "Approved by <your email>".
- **PASS ✅** if the run is Done.

### T21 – Safe test playbook: REJECT
- **DO:** run the same playbook again on DESKTOP-7KQ2M → in Approvals press **✖ Reject**.
- **YOU WILL SEE:** the run is **Stopped** and the last step is *Skipped*. **Approvals → History** shows both entries with your email and the time.
- **PASS ✅** if the run stopped.

### T22 – Run a real playbook from an alert ("Contain password guessing")
- **DO:**
  1. MAIN PC → **Alerts** → click the **"Password guessing … aibootest8"** alert from DESKTOP-7KQ2M → **▶ Run playbook**.
  2. The window shows: playbook **Contain password guessing** chosen, PC = DESKTOP-7KQ2M, User = `aibootest8`.
  3. The **IP address** is empty (runas has no IP). Type `45.95.147.3` → **▶ Start**.
- **WHAT HAPPENS:** 3 steps run on PC2: block the IP, disable the user for 30 minutes, tell the dashboard.
- **YOU WILL SEE:**
  - **▶ Runs**: ✅ Block IP 45.95.147.3, ✅ Disable account aibootest8 (30 min), ✅ Notify.
  - Bell: "Blocked 45.95.147.3 and disabled account aibootest8 for 30 min on DESKTOP-7KQ2M".
  - On PC2: `net user aibootest8` shows **Active No**. The T14 firewall command shows one more `AiBoO_Block_45_95_147_3_...` rule.
- **UNDO:** Isolation & Termination → PC2 → **Lift account restriction now** → `aibootest8`.
- **PASS ✅** if all 3 steps are ✅ and both changes are visible on PC2.

### T23 – Every one-click action on PC2
**WHERE:** MAIN PC → **Agent Console** → **Isolation & Termination** → PC: **DESKTOP-7KQ2M**. For each row, choose the Action, type the Target, then click **Dispatch**.
**YOU WILL SEE** for each row: `✅ Done on DESKTOP-7KQ2M: <what the agent did>`, unless the row says otherwise.

| # | Action | Target | Check on PC2 | Pass if |
|---|---|---|---|---|
| a | **Terminate process** (first open Notepad on PC2) | `notepad.exe` | Notepad closes | ✅ closed |
| b | **Block IP (inbound)** | `203.0.113.50` | WINDOW C: `Get-NetFirewallRule -DisplayName "AiBoO_Block_203*"` | rule shown |
| c | **Isolate IP (inbound)** | `203.0.113.51` | WINDOW C: `Get-NetFirewallRule -DisplayName "AiBoO_Isolate_*"` | rule shown |
| d | **Throttle IP / range 256 kbps, 30 min** | `1.1.1.1` | WINDOW C: `Get-NetQosPolicy -PolicyStore ActiveStore` | policy `AiBoO-Throttle-1-1-1-1-32` |
| e | **Remove throttle** | `1.1.1.1` | run the same command again | policy gone |
| f | **Restrict account 30 min (auto re-enable)** | `aibootest8` | `net user aibootest8` | Active **No** |
| g | **Lift account restriction now** | `aibootest8` | `net user aibootest8` | Active **Yes** |
| h | **Revoke identity** | `aibootest10` | `net user aibootest10` | Active **No**. Undo: `net user aibootest10 /active:yes` |
| i | **Force logout** | `aibootest10` | answer ❌ *"'aibootest10' has no open session on this PC (nothing to log off)"* | this message is **correct**: nobody is signed in as that user, and the agent asked Windows for real |
| j | **Lock screen (user must sign in again)** | `pc2user` | PC2 screen locks | ✅ locked |
| k | **Pseudo-lock** (decoy trap) | `pilot-decoy` | message `Decoy listening on ...:PORT`. Agent Console → tab **Locks**: one **ACTIVE** lock for DESKTOP-7KQ2M with **Decoy port** | lock shown |
| l | **Quarantine device** | `DEV-TEST1` | answer ❌ *"Device quarantine needs a network access control (NAC) / switch integration, which is not connected ..."* | this honest refusal is **correct** (NAC isn't built yet) |
| m | Own account protection: **Restrict account 30 min** | `pc2user` (YOU) | answer ❌ refused: AiBoO never locks out the account it runs as | refusal = **correct** |

**Extra test for row k (decoy hit):**
1. In WINDOW C, type `Test-NetConnection 127.0.0.1 -Port PORT`, using the port from the message.
2. Answer: `TcpTestSucceeded : True`. The Locks tab may show **1 hit(s)**.
3. Then click **Restore** on the lock. It changes to **RESTORED** (decoy closed).

**Isolation & Termination list:** all actions above appear in the list. Use the filter buttons: Terminated, Isolated, Pseudo-Locked, Failed.

### T24 – Freeze door badge (optional, needs a free test website)
- **DO:**
  1. Open https://webhook.site → copy **Your unique URL**.
  2. MAIN PC `backend\.env`: add the line `BADGE_WEBHOOK_URL=<that URL>`. Restart the backend (Ctrl+C → `npm run dev`).
  3. Dashboard → **Freeze Badge** → `EMP-1042` → Confirm.
- **YOU WILL SEE:** a green message. On webhook.site, a request containing `"action":"freeze_badge","badge_id":"EMP-1042"`.
- **UNDO:** remove the line from `.env` and restart the backend.
- **PASS ✅** if webhook.site received the request.

### T25 – Make your own multi-step playbook (editor) and run it on PC2
- **DO:**
  1. **Response → 📘 Playbooks → ＋ New playbook**. Name: `Pilot PC2 playbook`.
  2. Step 1: **Action** = *Disable account for N minutes*, Target `{user}`, Minutes `2`.
  3. Click **＋ ✋ Wait for approval**, then **＋ 📣 Notify dashboards**. Message: `Done for {user} on {pc}`.
  4. Use **↑** to move the approval step to the top: approval → disable → message.
  5. **💾 Save playbook**. The card shows **CUSTOM v1**.
  6. **▶ Run** → PC: **DESKTOP-7KQ2M**, User name: `aibootest8` → Start → Approvals → **✔ Approve**.
- **YOU WILL SEE:**
  - Runs: all ✅. Bell: "Done for aibootest8 on DESKTOP-7KQ2M".
  - `net user aibootest8` shows **Active No**, then **Yes** again by itself after about 2–3 minutes.
- **PASS ✅** if it disabled the account and turned it back on by itself.

### T26 – Edit, switch off, copy, delete
- **DO:**
  1. On `Pilot PC2 playbook`: **✎ Edit** → untick **Enabled** → Save. **▶ Run** is now grey.
  2. On a built-in playbook (e.g. "Contain password guessing"): there is no Edit or Delete. Click **⧉ Copy & edit** → Save → a new CUSTOM card.
  3. **🗑 Delete** the copy. Keep `Pilot PC2 playbook` until the end of the test.
- **PASS ✅** if all 3 work.

---

# PART 6 – AUTOMATIC RESPONSE RULES ON PC2

A **rule** means: *WHEN this attack happens on this PC, THEN run this playbook* — by itself, after one click, or only as a message.

⚠ Before every round, `net user aibootest8` must say **Active Yes**, and **10 minutes** must have passed since the last wrong-password round. Use the waits for Part 7.

### T27 – Make the playbook and the rule (TEST MODE)
- **DO:**
  1. **Playbooks → ＋ New playbook**. Name: `Rule test - disable user 2 min`. Step 1: *Disable account for N minutes*, Target `{user}`, Minutes `2`. Add **＋ 📣 Notify**: `Rule disabled {user} on {pc} for 2 min`. **💾 Save**.
  2. **⚙ Rules → ＋ New rule**:
     - Name: `Pilot PC2 rule`
     - Attack type: tick **Password guessing** and **Account locked out**
     - Risk at least: `35`
     - TriGate verdict: tick **BLOCK** and **HOLD**. (HOLD too, because T17 made password scores lower.)
     - Only these PCs: `DESKTOP-7KQ2M`
     - Where the attack comes from: **Any (or no IP)**
     - Time of day: **Any time**
     - THEN: **⚡ Run automatically**, playbook **Rule test - disable user 2 min**
     - **🧪 Test mode**: leave it **ticked**
     - **💾 Save rule**.
  3. On the rule card, click **🔍 Test against old alerts**.
- **YOU WILL SEE:**
  - The card **#1 Pilot PC2 rule**, ⚡ Run automatically, 🧪 test mode, ON.
  - "Last 30 days: this rule would have matched N of M TriGate alerts". N should be 3 or more, from your password attacks on PC2.
- **PASS ✅** if the rule is saved and the old-alert check shows PC2's password alerts.

### T28 – Rule in test mode: nothing happens ⏰
- **DO (WINDOW B):** `runas /user:aibootest8 cmd` with a wrong password, **exactly 5 times**.
- **YOU WILL SEE:** **⚙ Rules → ⟳ Refresh → 📜 Activity**: **🧪 Test mode - nothing done** · *"TEST MODE - would have: run "Rule test - disable user 2 min". Matched: Password guessing on DESKTOP-7KQ2M (...)"*
  - `net user aibootest8` still shows **Active Yes**.
  - The normal approval still appears in Approvals → **✖ Reject** it.
- **PASS ✅** if the activity says test mode and nothing changed.

### T29 – Rule ON: PseudoLock acts BY ITSELF ⏰
- **DO:**
  1. Rule card → **✎ Edit** → untick **🧪 Test mode**. A yellow warning appears → **💾 Save rule**.
  2. After the 10-minute wait: wrong password **exactly 5 times**.
- **WHAT HAPPENS:** nobody clicks anything. AiBoO runs the playbook on PC2 by itself.
- **YOU WILL SEE:**
  - Bell: **"Rule disabled aibootest8 on DESKTOP-7KQ2M for 2 min"**.
  - Activity: **▶ Ran playbook** · "Started ... automatically".
  - **Runs**: a purple **⚙ automatic (rule)** badge.
  - **Approvals**: **no** new card.
  - `net user aibootest8` shows **Active No**, then **Yes** again by itself after about 2 minutes.
- **PASS ✅** if the account was disabled with no click.

### T30 – Cooldown: the same attack is not handled twice ⏰
- **DO:** wait 10 minutes (it must still be less than 30 minutes since T29). Wrong password **exactly 5 times**.
- **YOU WILL SEE:**
  - Activity: **⏸ Cooldown - already handled** · "Already handled N min ago (cooldown 30 min)".
  - The account stays **Active Yes**.
- **PASS ✅** if it says cooldown.

### T31 – "Ask first": the rule asks, and you approve ⏰
- **DO:**
  1. Rule card → **✎ Edit** → **✋ Ask first** → **💾 Save rule**.
  2. After 10 minutes, wrong password **exactly 5 times**.
- **YOU WILL SEE:**
  - Bell: "Approval needed – Rule "Pilot PC2 rule" wants to run "Rule test - disable user 2 min" on DESKTOP-7KQ2M ...".
  - In Approvals: a card with a grey **Response rule** label.
- **DO:** **✔ Approve & start**.
- **YOU WILL SEE:**
  - History: **✅ Playbook ... started**.
  - Runs: "started by Rule ... (approved by <you>)".
  - `net user aibootest8` shows **Active No** (back to Yes after 2 minutes).
- **PASS ✅** if the playbook ran only after your click.

### T32 – Rule for another PC must NOT act on PC2 ⏰
- **DO:**
  1. Rule card → **✎ Edit** → Only these PCs: change it to `gorilla` → Save.
  2. After 10 minutes, wrong password **exactly 5 times** on PC2.
- **YOU WILL SEE:**
  - Activity: **no** new line for this attack.
  - Instead, the **normal** TriGate approval for aibootest8 appears (if the verdict is BLOCK). **✖ Reject** it.
- **PASS ✅** if the rule ignored PC2.

### T33 – Switch the rule off
- **DO:** switch the rule **OFF**.
- **YOU WILL SEE:** the card turns grey and shows **OFF**.
- **PASS ✅**

---

# PART 7 – DASHBOARD SCREENS WITH PC2 DATA
(You can do these during the 10-minute waits in Part 6.)

### T34 – Alerts: handle an alert from start to end
- **DO:** MAIN PC → **Alerts**. Click a PC2 alert, e.g. "Password guessing – aibootest8", then:
  1. **👀 Acknowledge**: the status becomes *acknowledged*.
  2. "Assign to": `soc-team` → **👤 Assign**.
  3. Type a note → **📝 Add note**.
  4. Choose **False alarm** → **✅ Close**.
  5. **↩ Reopen**, then close again with **Resolved**.
  6. Tick 2–3 rows on the left → blue bar → **Acknowledge** them all at once.
  7. **⬇ Export CSV** → open it in Excel.
- **YOU WILL SEE:**
  - The details show **PC = DESKTOP-7KQ2M**, the user, and Trust / Intent / Impact.
  - "History" at the bottom: created → acknowledged → assigned → note → closed → reopened → closed.
  - The CSV has PC2's alerts.
- **PASS ✅** if every button worked.

### T35 – Executive screen
- **DO:** MAIN PC → **Executive** → switch between **7 days / 30 days**.
- **YOU WILL SEE:**
  - Key figures, security posture, trend chart, top attack types, most targeted users (**aibootest8** should be at the top), top attacking IPs (**45.95.147.3**).
  - Protection status: threat feeds, behaviour learning.
- **PASS ✅** if PC2's attacks are counted.

### T36 – Reports (PDF + CSV)
- **DO:** MAIN PC → **Reports** → period **Last 24 hours** or **Last 7 days** → **Executive Security Summary ⬇ PDF**, **Risk Report ⬇ PDF** and **⬇ CSV**, **Compliance Report ⬇ PDF**.
- **YOU WILL SEE:** the PDFs open. The alerts in them come from **DESKTOP-7KQ2M** (and gorilla). The Compliance PDF has a section for **each** PC.
- **PASS ✅** if PC2 is in the reports.

### T37 – Fix one compliance problem on PC2
- **DO:**
  1. Reports → Compliance checks → **DESKTOP-7KQ2M** → tick **only gaps**.
  2. Pick an easy one. Example: if **Account lockout** is warning/fail, run in WINDOW B: `net accounts /lockoutthreshold:10`
  3. Restart the agent on PC2 (WINDOW A: Ctrl+C → `python main.py`), wait 1 minute, and reload Reports.
- **YOU WILL SEE:** that check turns **pass**, and PC2's score goes up.
- **PASS ✅** if the score changed. If PC2 has no easy gap, write "nothing to fix" and pass.

### T38 – Viewer can only look (optional)
- **DO:** log in as a user with the **viewer** role.
- **YOU WILL SEE:** Response, Rules and Alerts are visible, but **no** Approve, Reject, Run, Dispatch or Edit buttons.
- **PASS ✅**

---

# PART 8 – STABILITY TESTS (internet problems, restarts)

### T39 – PC2 loses internet, then events arrive later
- **DO:**
  1. On PC2, turn **Wi-Fi off** (or unplug the cable).
  2. After about 1 minute, MAIN PC → **Endpoints**: PC2 shows **Offline · last seen <time>**.
  3. While PC2 is offline: Response → Playbooks → Safe test → Run → PC: DESKTOP-7KQ2M.
     → Error: **"PC 'DESKTOP-7KQ2M' is not connected - start the agent on that PC first"**. This is correct.
  4. While offline, on PC2 WINDOW B: `net user aibootest12 Test@12345 /add`
  5. Turn **Wi-Fi on** again.
- **YOU WILL SEE:**
  - PC2 WINDOW A: `Command channel disconnected - will reconnect automatically`, then `Command channel CONNECTED ...` again.
  - Endpoints: PC2 is **Online** again.
  - The card **"New user account created" (aibootest12)** arrives **late**. The agent kept it while offline and sent it afterwards.
- **UNDO:** `net user aibootest12 /delete`
- **PASS ✅** if PC2 came back by itself and the late card arrived.

### T40 – MAIN PC backend restarts
- **DO:** MAIN PC, backend window: **Ctrl+C**, wait 20 seconds, then `npm run dev`.
- **YOU WILL SEE:**
  - PC2 WINDOW A shows disconnected, then **CONNECTED** again by itself within about 1 minute. You don't touch PC2.
  - Alerts are still there after the restart (saved in the database).
- **PASS ✅** if PC2 reconnected by itself.

### T41 – ngrok restarts
- **DO:** MAIN PC ngrok window: **Ctrl+C**, then start ngrok again (same command as in S6).
- **YOU WILL SEE:**
  - With a **fixed** address, PC2 reconnects by itself ✅.
  - **Without** a fixed address, the address is new, so PC2 stays offline. Put the new address in PC2's `config.ini` (P6) and restart the agent. (This is why a fixed ngrok address, or later a real server, is needed for a real pilot.)
- **PASS ✅** if PC2 is online again.

---

# PART 9 – CLEAN UP (important – do all of it)

**PC2, WINDOW B (Admin cmd):**
```
net user aibootest8 /delete
net user aibootest9 /delete
net user aibootest10 /delete
net user aibootest11 /delete
net user aibootest12 /delete
sc delete AiBooTestSvc
schtasks /delete /tn AiBooTestTask /f
```
Some lines may say "not found" if you already deleted them. That's fine.

**PC2, WINDOW C (Admin PowerShell):**
```
Remove-NetFirewallRule -DisplayName "AiBoO_Block_*"
Remove-NetFirewallRule -DisplayName "AiBoO_Isolate_*"
Get-NetQosPolicy -PolicyStore ActiveStore | Where-Object Name -like "AiBoO-*" | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false
netsh advfirewall show allprofiles state
```
The last command must show **State ON** for all 3 profiles.

**PC2, files:**
- `C:\AiBoO\agent\config\ip_blocklist.txt`: delete the lines `45.95.147.3` and `1.1.1.1`.
- To reset what TriGate learned (False alarm etc.): stop the agent and delete `C:\AiBoO\agent\trigate_memory.json`.

**MAIN PC dashboard:**
- **⚙ Rules**: 🗑 delete `Pilot PC2 rule`.
- **📘 Playbooks**: 🗑 delete `Rule test - disable user 2 min` and `Pilot PC2 playbook` (only possible after the rule is deleted).
- **Endpoints**: PC2's importance must be **Normal**.
- **Agent Console → Locks**: click **Restore** on any lock that is still ACTIVE.
- If you used T24: remove `BADGE_WEBHOOK_URL` from `backend\.env`.

**MAIN PC:** close ngrok (Ctrl+C) when the test is finished.

---

# PART 10 – RESULT SHEET (tick and send me a photo or screenshot)

| Test | What | Result |
|---|---|---|
| P3 | PC2 reaches the MAIN PC (/health ok) | [ ] pass [ ] fail |
| P10 | Agent says Command channel CONNECTED | [ ] pass [ ] fail |
| T1 | PC2 Online on Endpoints | [ ] pass [ ] fail |
| T2 | PC2 in the agent list | [ ] pass [ ] fail |
| T3 | Remote lock screen worked | [ ] pass [ ] fail |
| T4 | PC2 compliance shown | [ ] pass [ ] fail |
| T5 | Audit policy changed card | [ ] pass [ ] fail |
| T6 | New user card (HOLD) | [ ] pass [ ] fail |
| T7 | Password guessing BLOCK + Approve disabled the account + Lift | [ ] pass [ ] fail |
| T8 | Secret admin BLOCK + Approve disabled aibootest9 | [ ] pass [ ] fail |
| T9 | Attack chain (Correlated) | [ ] pass [ ] fail |
| T10 | Importance Critical raised the risk | [ ] pass [ ] fail |
| T11 | Suspicious service card | [ ] pass [ ] fail |
| T12 | Scheduled task card | [ ] pass [ ] fail |
| T13 | Reject changed nothing + False alarm saved | [ ] pass [ ] fail |
| T14 | Internet bad IP → Approve → firewall rule on PC2 | [ ] pass [ ] fail |
| T15 | Real bad-IP connection found + program stopped | [ ] pass [ ] fail |
| T16 | Firewall OFF lowered Trust + memory kept | [ ] pass [ ] fail |
| T17 | False alarm lowered the next score | [ ] pass [ ] fail |
| T18 | Account locked out card (optional) | [ ] pass [ ] fail [ ] skipped |
| T19 | Security log cleared card (optional) | [ ] pass [ ] fail [ ] skipped |
| T20 | Safe playbook Approve → Done | [ ] pass [ ] fail |
| T21 | Safe playbook Reject → Stopped | [ ] pass [ ] fail |
| T22 | Contain password guessing from an alert | [ ] pass [ ] fail |
| T23 a–m | One-click actions (write which letters failed: ____ ) | [ ] pass [ ] fail |
| T24 | Freeze badge webhook (optional) | [ ] pass [ ] fail [ ] skipped |
| T25 | Own playbook with approval | [ ] pass [ ] fail |
| T26 | Edit / off / copy / delete | [ ] pass [ ] fail |
| T27 | Rule saved + test against old alerts | [ ] pass [ ] fail |
| T28 | Test mode did nothing | [ ] pass [ ] fail |
| T29 | Rule acted by itself | [ ] pass [ ] fail |
| T30 | Cooldown | [ ] pass [ ] fail |
| T31 | Ask first → Approve & start | [ ] pass [ ] fail |
| T32 | Rule for gorilla ignored PC2 | [ ] pass [ ] fail |
| T33 | Rule switched off | [ ] pass [ ] fail |
| T34 | Alerts handling | [ ] pass [ ] fail |
| T35 | Executive shows PC2 data | [ ] pass [ ] fail |
| T36 | PDF / CSV reports include PC2 | [ ] pass [ ] fail |
| T37 | Compliance fix raised the score | [ ] pass [ ] fail |
| T38 | Viewer can only look (optional) | [ ] pass [ ] fail [ ] skipped |
| T39 | Offline → back online + late card | [ ] pass [ ] fail |
| T40 | Backend restart → PC2 reconnects | [ ] pass [ ] fail |
| T41 | ngrok restart | [ ] pass [ ] fail |
| Clean up | Part 9 done | [ ] done |

**For every FAIL, send me:** the test number, a screenshot of the dashboard, and the last 20 lines of PC2's WINDOW A.

---

## If something goes wrong

| Problem | Reason | Fix |
|---|---|---|
| PC2 window: `connect error` | wrong `api_key` or `remote_url` | check P6, then Ctrl+C and `python main.py` |
| PC2 not in Endpoints | ngrok closed, or the address changed | restart ngrok (S6), update P6 |
| No card after an attack | Windows logging is off | do P7 again; the agent must run **as Administrator** |
| `runas` says **1909 … locked out** | too many wrong passwords | `net user aibootest8 /active:yes` or wait 10 minutes |
| Card shows **gorilla** instead of PC2 | `endpoint_name` in PC2's config is still gorilla | change it to PC2's name, then restart the agent |
| No approval appears | verdict was HOLD (approvals only for BLOCK), or a rule handled it | normal; use the manual action in Isolation & Termination |
| Agent window stops moving | someone clicked inside it (QuickEdit) | press Esc in the window; do P9 |
| Approve says "not connected" | PC2 went offline | check PC2's internet and ngrok, then try again |
