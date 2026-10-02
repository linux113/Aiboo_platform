AiBoO Agent - quick start
=========================

What is in this folder
  AiBoO-Agent.exe        the agent (no Python needed)
  config.ini             settings - the server address is asked the first time
  run_agent.bat          start the agent in a window (best for testing)
  install_service.bat    install as a Windows service (always on, starts with Windows)
  uninstall_service.bat  remove the service
  configure.ps1          used by the two .bat files (asks the settings)
  config\                event rules + your own bad-IP list (ip_blocklist.txt)
  nssm.exe               helper that runs the agent as a service

Before you start - on the SERVER PC (the PC with the dashboard)
  1. backend running   (cd backend - npm run dev)
  2. ngrok running     (ngrok http 4000)  -> copy the https://....ngrok-free.dev address
     (same office network instead: use http://<server PC IP>:4000 and open port 4000)

On THIS PC
  A) Test with a window
     1. Right-click run_agent.bat - "Run as administrator".
     2. Type the server address (the ngrok address) - press ENTER for the API key.
     3. Wait for the line:  Command channel CONNECTED ... as endpoint '<this PC>'
     4. The dashboard - Endpoints page - shows this PC as Online.
     Keep the window open. Do not click inside it. Close it to stop the agent.

  B) Always on (Windows service)
     1. Right-click install_service.bat - "Run as administrator".
     2. Type the server address. The installer copies everything to
        C:\Program Files\AiBoO, starts the service and shows the last log lines.
     3. Log file: C:\Program Files\AiBoO\logs\agent.log
     Do not use A and B at the same time.

  The ngrok address changed?  Run run_agent.bat (or install_service.bat) again and
  type the new address - or edit remote_url in config.ini and restart.

Windows / antivirus warnings
  "Windows protected your PC": click "More info" - "Run anyway" (the exe is not signed).
  If the antivirus removes AiBoO-Agent.exe, add an exclusion for this folder.

Problems
  "connect error" in the log      -> server address or API key wrong (run the .bat again)
  "cannot reach the server"       -> backend or ngrok not running on the server PC
  This PC shows another PC's name -> endpoint_name in config.ini - the .bat files fix it
