@echo off
setlocal enabledelayedexpansion
title AiBoO Plugin - Installer

cd /d "%~dp0"

echo ============================================
echo    AiBoO Security Log Plugin
echo    Installer for remote log forwarding
echo ============================================
echo.
echo This will install a background service that
echo forwards Windows Security events from this
echo PC to your AiBoO dashboard.
echo.
echo Requirements: Windows 10/11, PowerShell
echo.

REM ---- Admin privilege check ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] This installer must be run as Administrator.
    echo   Right-click ^&gt; Run as Administrator
    pause
    exit /b 1
)

REM ---- Clean up any existing task first ----
schtasks /query /tn "AiBoO Security Plugin" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Removing existing scheduled task...
    schtasks /end /tn "AiBoO Security Plugin" >nul 2>&1
    schtasks /delete /tn "AiBoO Security Plugin" /f >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [OK] Old task removed.
    ) else (
        echo [WARN] Could not remove old task, continuing...
    )
)

REM --- Kill any running agent processes from previous install ---
echo [INFO] Stopping any running agent processes...
taskkill /FI "IMAGENAME eq powershell.exe" /FI "WINDOWTITLE like AiBoO Security Plugin%" /F >nul 2>&1
taskkill /FI "IMAGENAME eq powershell.exe" /FI "WINDOWTITLE like *agent.ps1*" /F >nul 2>&1

REM --- Get server IP ---
:GET_IP
echo.
echo Enter the IP of the PC running the AiBoO dashboard.
set /p SERVER="Dashboard IP: "
if "%SERVER%"=="" goto GET_IP

REM --- Validate IP format ---
echo %SERVER% | findstr /r "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Invalid IP format. Please enter a valid IPv4 address.
    goto GET_IP
)

REM --- Validate each octet is 0-255 ---
for /f "tokens=1-4 delims=." %%a in ("%SERVER%") do (
    if %%a LSS 0 goto BAD_OCTET
    if %%a GTR 255 goto BAD_OCTET
    if %%b LSS 0 goto BAD_OCTET
    if %%b GTR 255 goto BAD_OCTET
    if %%c LSS 0 goto BAD_OCTET
    if %%c GTR 255 goto BAD_OCTET
    if %%d LSS 0 goto BAD_OCTET
    if %%d GTR 255 goto BAD_OCTET
)
goto OCTET_OK
:BAD_OCTET
echo [ERROR] IP octet out of range (0-255). Please enter a valid IPv4 address.
goto GET_IP
:OCTET_OK

REM --- Test connection BEFORE saving config ---
echo.
echo Testing connection to dashboard server...
set CONNECTION_OK=0
for /l %%i in (1,1,3) do (
    powershell -Command "try { $r = Invoke-RestMethod -Uri 'http://%SERVER%:8001/health' -TimeoutSec 3; Write-Host '[OK] Server reachable on port 8001' -ForegroundColor Green; exit 0 } catch { exit 1 }" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set CONNECTION_OK=1
        goto CONNECTION_TEST_DONE
    )
    echo   Retry %%i/3...
    timeout /t 2 /nobreak >nul
)
:CONNECTION_TEST_DONE

if %CONNECTION_OK% EQU 1 (
    echo [OK] Server is reachable.
) else (
    echo [WARN] Could not reach %SERVER%:8001. Server might be offline.
    echo   You can still continue and it will work once the server is started.
)

REM --- Save config ---
echo %SERVER%>"%~dp0config.txt"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to write config file.
    pause
    exit /b 1
)
echo [OK] Config saved: %SERVER%

REM --- Install scheduled task ---
set TASK_NAME=AiBoO Security Plugin
set SCRIPT_PATH=%~dp0agent.ps1

echo.
echo Creating scheduled task (runs every 60 seconds)...

schtasks /create /tn "%TASK_NAME%" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT_PATH%\"" ^
    /sc minute /mo 1 /ru SYSTEM /f

if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] Could not create scheduled task.
    echo   Try running this installer as Administrator.
    pause
    exit /b 1
)

echo [OK] Plugin installed as background task.
echo [OK] Runs every 60 seconds (hidden, no window).
echo [OK] Forwards: failed logons, logons, admin use, processes, connections
echo.

echo ============================================
echo    Installation complete!
echo ============================================
echo.
echo The plugin is now running in the background.
echo Logs from this PC will appear in your
echo AiBoO dashboard within 1-2 minutes.
echo.
echo To remove later, run: uninstall.bat
echo.
pause
