@echo off
title AiBoO - Close Firewall Ports
setlocal enabledelayedexpansion

echo ============================================
echo  Closing AiBoO Firewall Rules
echo ============================================
echo.

REM ---- Admin check ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)

for %%p in ("Agent API (8001)" "Backend API (4000)" "CV Service (5050)") do (
    set "RULE_NAME=AiBoO v2 - %%~p"
    netsh advfirewall firewall show rule name="AiBoO v2 - %%~p" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        netsh advfirewall firewall delete rule name="AiBoO v2 - %%~p" >nul
        echo   Removed: AiBoO v2 - %%~p
    ) else (
        echo   Not found: AiBoO v2 - %%~p
    )
)

echo.
echo All AiBoO firewall rules removed.
pause
