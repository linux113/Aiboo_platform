@echo off
title AiBoO - Open Firewall Ports
setlocal enabledelayedexpansion

echo ============================================
echo  Opening Windows Firewall for remote log access
echo ============================================
echo.

REM ---- Admin check ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] This script must be run as Administrator.
    echo   Right-click ^&gt; Run as Administrator
    pause
    exit /b 1
)

set IP_RANGES=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12

REM ---- Port 8001: Agent API ----
netsh advfirewall firewall show rule name="AiBoO v2 - Agent API (8001)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    netsh advfirewall firewall delete rule name="AiBoO v2 - Agent API (8001)" >nul
    echo   Removed existing rule for port 8001.
)
netsh advfirewall firewall add rule name="AiBoO v2 - Agent API (8001)" ^
    dir=in action=allow protocol=TCP localport=8001 ^
    remoteip=%IP_RANGES% profile=Private
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create rule for port 8001.
) else (
    echo   Port 8001 (Agent API) opened on Private networks.
)

REM ---- Port 4000: Backend API ----
netsh advfirewall firewall show rule name="AiBoO v2 - Backend API (4000)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    netsh advfirewall firewall delete rule name="AiBoO v2 - Backend API (4000)" >nul
    echo   Removed existing rule for port 4000.
)
netsh advfirewall firewall add rule name="AiBoO v2 - Backend API (4000)" ^
    dir=in action=allow protocol=TCP localport=4000 ^
    remoteip=%IP_RANGES% profile=Private
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create rule for port 4000.
) else (
    echo   Port 4000 (Backend API) opened on Private networks.
)

REM ---- Port 5050: CV Service ----
netsh advfirewall firewall show rule name="AiBoO v2 - CV Service (5050)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    netsh advfirewall firewall delete rule name="AiBoO v2 - CV Service (5050)" >nul
    echo   Removed existing rule for port 5050.
)
netsh advfirewall firewall add rule name="AiBoO v2 - CV Service (5050)" ^
    dir=in action=allow protocol=TCP localport=5050 ^
    remoteip=%IP_RANGES% profile=Private
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create rule for port 5050.
) else (
    echo   Port 5050 (CV Service) opened on Private networks.
)

echo.
echo ============================================
echo  Your IP address for remote machines:
echo ============================================
ipconfig | findstr /i "IPv4"
echo.
echo ============================================
echo  On remote PCs, run:
echo    powershell -File "remote-log-sender.ps1" ^
echo      -ServerUrl "http://YOUR_IP:8001"
echo ============================================
echo.
echo  To remove these rules later, run: close-firewall.bat
echo.
pause
