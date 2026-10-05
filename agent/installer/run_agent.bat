@echo off
setlocal EnableExtensions
title AiBoO Agent - start in the background
cd /d "%~dp0"

set "EXE=%~dp0AiBoO-Agent.exe"
set "INI=%~dp0config.ini"

net session >nul 2>&1
if errorlevel 1 goto :noadmin
if not exist "%EXE%" goto :noexe

rem ---- is the agent already running? --------------------------------------
tasklist /FI "IMAGENAME eq AiBoO-Agent.exe" 2>nul | find /I "AiBoO-Agent.exe" >nul
if not errorlevel 1 (
    echo [i] The AiBoO agent is ALREADY running in the background - nothing to do.
    echo     Status and log : show_status.bat
    echo     Stop it        : stop_agent.bat
    timeout /t 6 /nobreak >nul
    exit /b 0
)
sc query AiBoO_Agent 2>nul | find "RUNNING" >nul
if not errorlevel 1 (
    echo [!] The AiBoO Windows service is already running on this PC.
    echo     Do not run the agent twice. Stop it first:  sc stop AiBoO_Agent
    timeout /t 10 /nobreak >nul
    exit /b 1
)

rem ---- settings: only the first time, or when /setup is given --------------
if not exist "%INI%" goto :setup
findstr /I /C:"your-ngrok-url" "%INI%" >nul 2>&1
if not errorlevel 1 goto :setup
findstr /I /C:"http" "%INI%" >nul 2>&1
if errorlevel 1 goto :setup
if /I "%~1"=="/setup" goto :setup

echo [i] Server address already saved in config.ini - keeping it.
echo     Change it with:  run_agent.bat /setup
echo.
goto :start

:setup
echo ------------------------------------------------------------
echo   First-time settings - answer the questions below.
echo   This window closes by itself when the agent has started.
echo ------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure.ps1"
if errorlevel 1 goto :setupfailed
echo.

:start
echo Starting the AiBoO agent in the background - no window will stay open.
start "" /d "%~dp0." "%EXE%"
timeout /t 5 /nobreak >nul

tasklist /FI "IMAGENAME eq AiBoO-Agent.exe" 2>nul | find /I "AiBoO-Agent.exe" >nul
if errorlevel 1 goto :nostart

echo.
echo ============================================================
echo   [OK] The AiBoO agent is RUNNING IN THE BACKGROUND.
echo        The client sees no window and nothing on the screen.
echo ============================================================
echo   Status and log     : show_status.bat
echo   Stop the agent     : stop_agent.bat
echo   Start with Windows : install_service.bat
echo.
echo This window closes by itself in a few seconds.
timeout /t 5 /nobreak >nul
exit /b 0

:noadmin
echo [ERROR] Please run this file as Administrator:
echo         right-click run_agent.bat then "Run as administrator".
echo         Without Administrator rights the agent cannot read the Windows security log.
echo.
pause
exit /b 1

:noexe
echo [ERROR] AiBoO-Agent.exe is not in this folder.
echo         Build it first on a Windows PC with agent\build_agent.bat,
echo         then use the dist.zip it creates.
pause
exit /b 1

:setupfailed
echo.
echo [ERROR] Settings were not saved - the agent was NOT started.
pause
exit /b 1

:nostart
echo.
echo [!] The agent did not stay running. Look at the log to see why:
echo     show_status.bat
pause
exit /b 1
