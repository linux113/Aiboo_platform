@echo off
setlocal EnableExtensions
title AiBoO Agent - status and log
cd /d "%~dp0"

set "LOG=%~dp0logs\agent-stdout.log"
if not exist "%LOG%" if exist "C:\Program Files\AiBoO\logs\agent.log" set "LOG=C:\Program Files\AiBoO\logs\agent.log"

echo ============================================================
echo   AiBoO agent - status
echo ============================================================
echo.
echo [1] Agent process running?
tasklist /FI "IMAGENAME eq AiBoO-Agent.exe" 2>nul | find /I "AiBoO-Agent.exe" >nul
if errorlevel 1 goto :notrunning
echo     RUNNING - in the background, no window is shown on screen.
goto :svc
:notrunning
echo     NOT running. Start it with run_agent.bat - "Run as administrator".
:svc
echo.
echo [2] Windows service AiBoO_Agent?
sc query AiBoO_Agent 2>nul | find "STATE"
if errorlevel 1 echo     not installed - the agent is running as a normal program.
echo.
echo [3] Windows logging "connected" check:
if not exist "%LOG%" goto :nolog
findstr /C:"Command channel CONNECTED" "%LOG%" >nul 2>&1
if errorlevel 1 goto :notconnected
echo     CONNECTED - this PC is Online on the dashboard (Endpoints page).
goto :logtail
:notconnected
echo     Not connected yet. Look at the lines below - "connect error" means the
echo     server address or the API key is wrong. Change it: run_agent.bat /setup
goto :logtail
:nolog
echo     No log file yet at %LOG%
echo     The agent has not been started from this folder yet.
echo.
pause
exit /b 0

:logtail
echo.
echo [4] Last 20 lines of the log file:
echo ------------------------------------------------------------
powershell -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 20"
echo ------------------------------------------------------------
echo.
echo Full log file: %LOG%
echo (Right-click - Open with - Notepad to read all of it.)
echo.
pause
exit /b 0
