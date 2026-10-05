@echo off
setlocal EnableExtensions
title AiBoO Agent - stop
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 goto :noadmin

sc query AiBoO_Agent 2>nul | find "RUNNING" >nul
if not errorlevel 1 goto :isservice

tasklist /FI "IMAGENAME eq AiBoO-Agent.exe" 2>nul | find /I "AiBoO-Agent.exe" >nul
if errorlevel 1 goto :notrunning

taskkill /IM AiBoO-Agent.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul
tasklist /FI "IMAGENAME eq AiBoO-Agent.exe" 2>nul | find /I "AiBoO-Agent.exe" >nul
if errorlevel 1 goto :stopped
echo [!] The agent is still running. Close it from Task Manager if needed.
echo.
pause
exit /b 1

:stopped
echo [OK] The AiBoO agent has been stopped.
echo      Start it again with run_agent.bat - "Run as administrator".
timeout /t 6 /nobreak >nul
exit /b 0

:notrunning
echo [i] The AiBoO agent is not running right now.
timeout /t 4 /nobreak >nul
exit /b 0

:isservice
echo [!] The agent is running as a WINDOWS SERVICE, not as a normal program.
echo     Stop it with   :  sc stop AiBoO_Agent
echo     Remove it with :  uninstall_service.bat - run that as Administrator
echo.
pause
exit /b 0

:noadmin
echo [ERROR] Please run this file as Administrator:
echo         right-click stop_agent.bat then "Run as administrator".
echo.
pause
exit /b 1
