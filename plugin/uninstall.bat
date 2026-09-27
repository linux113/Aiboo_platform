@echo off
setlocal enabledelayedexpansion
title AiBoO Plugin - Uninstaller

cd /d "%~dp0"

echo ============================================
echo    AiBoO Security Log Plugin
echo    Uninstaller
echo ============================================
echo.

REM ---- Admin privilege check ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] This uninstaller must be run as Administrator.
    echo   Right-click ^&gt; Run as Administrator
    pause
    exit /b 1
)

set TASK_NAME=AiBoO Security Plugin

REM --- Kill any running PowerShell processes from the task ---
echo [INFO] Stopping any running agent processes...
taskkill /FI "IMAGENAME eq powershell.exe" /FI "WINDOWTITLE eq *AiBoO*" /F >nul 2>&1
taskkill /FI "IMAGENAME eq powershell.exe" /FI "CMD eq *agent.ps1*" /F >nul 2>&1
echo [OK] Agent processes stopped.

REM --- Check if scheduled task exists before deleting ---
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Removing scheduled task...
    schtasks /end /tn "%TASK_NAME%" >nul 2>&1
    schtasks /delete /tn "%TASK_NAME%" /f
    if %ERRORLEVEL% EQU 0 (
        echo [OK] Scheduled task removed.
    ) else (
        echo [ERROR] Failed to remove scheduled task.
        pause
        exit /b 1
    )
) else (
    echo [INFO] No scheduled task found - nothing to remove.
)

REM --- Remove config file ---
if exist "%~dp0config.txt" (
    del "%~dp0config.txt"
    if %ERRORLEVEL% EQU 0 (
        echo [OK] Config file deleted.
    ) else (
        echo [WARN] Could not delete config file.
    )
) else (
    echo [INFO] No config file found.
)

REM --- Cleanup temp files ---
if exist "%TEMP%\aiboo_plugin_running.txt" (
    del "%TEMP%\aiboo_plugin_running.txt" >nul 2>&1
)
if exist "%TEMP%\aiboo_plugin_retry.json" (
    del "%TEMP%\aiboo_plugin_retry.json" >nul 2>&1
)
if exist "%TEMP%\aiboo_plugin_audit.csv" (
    del "%TEMP%\aiboo_plugin_audit.csv" >nul 2>&1
)
echo [OK] Temporary files cleaned.

echo.
echo ============================================
echo   Uninstall complete!
echo ============================================
echo.
echo [OK] Plugin removed.
echo [OK] No more logs forwarded from this PC.
echo.
pause
