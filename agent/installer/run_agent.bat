@echo off
setlocal EnableExtensions
title AiBoO Agent (window mode - keep this window open)
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this file as Administrator:
    echo         right-click run_agent.bat - "Run as administrator".
    echo         Without Administrator rights the agent cannot read the Windows security log.
    pause
    exit /b 1
)
if not exist "%~dp0AiBoO-Agent.exe" (
    echo [ERROR] AiBoO-Agent.exe is not in this folder. Build it first with build_agent.bat.
    pause
    exit /b 1
)
sc query AiBoO_Agent 2>nul | find "RUNNING" >nul
if not errorlevel 1 (
    echo [!] The AiBoO service is already running on this PC.
    echo     Do not run the agent twice. Stop the service first:  sc stop AiBoO_Agent
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure.ps1"
if errorlevel 1 (
    pause
    exit /b 1
)

echo Starting the agent. Look for "Command channel CONNECTED".
echo Do NOT click inside this window. Close it (or Ctrl+C) to stop the agent.
echo.
"%~dp0AiBoO-Agent.exe"
echo.
echo The agent has stopped.
pause
