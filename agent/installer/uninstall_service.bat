@echo off
setlocal EnableExtensions
title AiBoO Agent - remove service
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this file as Administrator.
    pause
    exit /b 1
)

set "SVC=AiBoO_Agent"
set "INSTALL_DIR=C:\Program Files\AiBoO"
set "NSSM=%~dp0nssm.exe"
if not exist "%NSSM%" set "NSSM=%INSTALL_DIR%\nssm.exe"

echo Stopping and removing the service %SVC% ...
"%NSSM%" stop "%SVC%" >nul 2>&1
"%NSSM%" remove "%SVC%" confirm
echo.
echo The service is removed. The folder %INSTALL_DIR% (log, settings, memory)
echo is kept. Delete it by hand if you no longer need it.
echo.
echo Firewall rules made by AiBoO (AiBoO_Block_*, AiBoO_Isolate_*) are NOT removed.
echo To remove them, in an Administrator PowerShell:
echo     Remove-NetFirewallRule -DisplayName "AiBoO_*"
echo.
pause
