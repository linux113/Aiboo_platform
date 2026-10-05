AiBoO Agent - quick start
=========================

What is in this folder
  AiBoO-Agent.exe        the agent (no Python needed). Runs WINDOWLESS:
                         once started it works in the background and the
                         client sees no window at all.
  config.ini             settings - the server address is asked the first time
  run_agent.bat          start the agent in the background (asks the settings
                         the first time, then closes its own window)
  show_status.bat        is it running? is it connected? + last log lines
  stop_agent.bat         stop the background agent
  install_service.bat    install as a Windows service (always on, starts with
                         Windows, also invisible - best for client PCs)
  uninstall_service.bat  remove the service
  configure.ps1          used by the .bat files (asks the settings)
  config\                event rules + your own bad-IP list (ip_blocklist.txt)
  nssm.exe               helper that runs the agent as a service

Before you start - on the SERVER PC (the PC with the dashboard)
  1. backend running   (cd backend - npm run dev)
  2. ngrok running     (ngrok http 4000)  -> copy the https://....ngrok-free.dev address
     (same office network instead: use http://<server PC IP>:4000 and open port 4000)

On THIS PC (the client PC)
  A) Normal start - runs in the background
     1. Right-click run_agent.bat - "Run as administrator".
     2. FIRST TIME ONLY: type the server address, press ENTER for the API key,
        check the name of this PC. Windows may ask "Do you want to allow..." -
        click Yes (that is the normal Windows Administrator question).
     3. The window says "[OK] The AiBoO agent is RUNNING IN THE BACKGROUND"
        and closes by itself after a few seconds.
     4. NOTHING stays on the screen - no black window, no log window.
        The agent keeps running until the PC is restarted (then run the .bat
        again) or until stop_agent.bat is used.
     Check it later with show_status.bat (it prints the last log lines).

  B) Always on - Windows service (no window either, starts with Windows)
     1. Right-click install_service.bat - "Run as administrator".
     2. Type the server address. The installer copies everything to
        C:\Program Files\AiBoO, starts the service and shows the last log lines.
     3. Log file: C:\Program Files\AiBoO\logs\agent-stdout.log
        (plus C:\Program Files\AiBoO\logs\agent.log)
     Do not use A and B at the same time.

  Where is the log in window mode?
     <this folder>\logs\agent-stdout.log   - written even though no window shows.
     show_status.bat prints the last 20 lines of it.

  The ngrok address changed?  Run run_agent.bat /setup (or install_service.bat
  again) and type the new address - or edit remote_url in config.ini and start
  the agent again.  (run_agent.bat alone keeps an address that is already saved;
  /setup forces the questions.)

Windows / antivirus warnings
  "Windows protected your PC": click "More info" - "Run anyway" (the exe is not signed).
  "Do you want to allow this app to make changes?" - click Yes: the agent must run
  as Administrator to read the Windows security log.
  If the antivirus removes AiBoO-Agent.exe, add an exclusion for this folder.

Problems
  "connect error" in the log      -> server address or API key wrong (run run_agent.bat /setup)
  "cannot reach the server"       -> backend or ngrok not running on the server PC
  This PC shows another PC's name -> endpoint_name in config.ini - run run_agent.bat /setup
  Nothing happens when I start it -> run show_status.bat and read the last lines
  No window at all is normal - the agent is meant to be invisible.
