@echo off
setlocal EnableExtensions
title AiBoO Agent - install as Windows service
cd /d "%~dp0"

echo =====================================================
echo   AiBoO Agent - install as a Windows service
echo   (starts by itself with Windows, no window needed)
echo =====================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this file as Administrator:
    echo         right-click install_service.bat - "Run as administrator".
    pause
    exit /b 1
)
if not exist "%~dp0AiBoO-Agent.exe" (
    echo [ERROR] AiBoO-Agent.exe is not in this folder.
    echo         Build it first on a Windows PC with agent\build_agent.bat,
    echo         then use the dist.zip it creates.
    pause
    exit /b 1
)

set "SVC=AiBoO_Agent"
set "INSTALL_DIR=C:\Program Files\AiBoO"

echo [1/6] Settings (server address, PC name, Windows logging)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure.ps1"
if errorlevel 1 (
    echo [ERROR] Settings were not saved - nothing installed.
    pause
    exit /b 1
)

echo [2/6] Removing an older AiBoO service (if there is one)...
sc query "%SVC%" >nul 2>&1
if not errorlevel 1 (
    "%~dp0nssm.exe" stop "%SVC%" >nul 2>&1
    "%~dp0nssm.exe" remove "%SVC%" confirm >nul 2>&1
    timeout /t 3 /nobreak >nul
)

echo [3/6] Copying files to %INSTALL_DIR% ...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"
copy /Y "%~dp0AiBoO-Agent.exe" "%INSTALL_DIR%\" >nul || goto :copyfail
copy /Y "%~dp0config.ini" "%INSTALL_DIR%\" >nul || goto :copyfail
copy /Y "%~dp0nssm.exe" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0uninstall_service.bat" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0stop_agent.bat" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0show_status.bat" "%INSTALL_DIR%\" >nul
if not exist "%INSTALL_DIR%\config" mkdir "%INSTALL_DIR%\config"
copy /Y "%~dp0config\event_rules.yaml" "%INSTALL_DIR%\config\" >nul
if not exist "%INSTALL_DIR%\config\ip_blocklist.txt" copy /Y "%~dp0config\ip_blocklist.txt" "%INSTALL_DIR%\config\" >nul

echo [4/6] Creating the service %SVC% ...
set "NSSM=%INSTALL_DIR%\nssm.exe"
"%NSSM%" install "%SVC%" "%INSTALL_DIR%\AiBoO-Agent.exe" >nul || goto :svcfail
"%NSSM%" set "%SVC%" AppDirectory "%INSTALL_DIR%" >nul
"%NSSM%" set "%SVC%" AppStdout "%INSTALL_DIR%\logs\agent.log" >nul
"%NSSM%" set "%SVC%" AppStderr "%INSTALL_DIR%\logs\agent.log" >nul
"%NSSM%" set "%SVC%" AppRotateFiles 1 >nul
"%NSSM%" set "%SVC%" AppRotateOnline 1 >nul
"%NSSM%" set "%SVC%" AppRotateBytes 10485760 >nul
"%NSSM%" set "%SVC%" AppEnvironmentExtra PYTHONUNBUFFERED=1 >nul
"%NSSM%" set "%SVC%" AppExit Default Restart >nul
"%NSSM%" set "%SVC%" AppRestartDelay 10000 >nul
"%NSSM%" set "%SVC%" Start SERVICE_AUTO_START >nul
"%NSSM%" set "%SVC%" DisplayName "AiBoO Security Agent" >nul
"%NSSM%" set "%SVC%" Description "AiBoO agent - watches Windows security events and runs the responses approved on the AiBoO dashboard." >nul

echo [5/6] Starting the service...
"%NSSM%" start "%SVC%" >nul 2>&1
echo       waiting 25 seconds for the agent to connect...
timeout /t 25 /nobreak >nul

echo [6/6] Last lines of the agent log:
echo -----------------------------------------------------
powershell -NoProfile -Command "if (Test-Path '%INSTALL_DIR%\logs\agent.log') { Get-Content '%INSTALL_DIR%\logs\agent.log' -Tail 15 } else { 'log not created yet' }"
echo -----------------------------------------------------
echo.
findstr /C:"Command channel CONNECTED" "%INSTALL_DIR%\logs\agent.log" >nul 2>&1
if errorlevel 1 (
    echo [!] Not connected yet. Wait 1 minute and check the log again:
    echo     notepad "%INSTALL_DIR%\logs\agent.log"
    echo     Look for "Command channel CONNECTED". If you see "connect error",
    echo     the server address or API key is wrong: run install_service.bat again.
) else (
    echo [OK] CONNECTED - this PC now shows as Online on the AiBoO dashboard - Endpoints page.
)
echo.
echo  Service : %SVC%   (check: sc query %SVC%)
echo  Folder  : %INSTALL_DIR%
echo  Log     : %INSTALL_DIR%\logs\agent.log
echo  Status  : "%INSTALL_DIR%\show_status.bat"  ^(running? connected? last log lines^)
echo  Remove  : "%INSTALL_DIR%\uninstall_service.bat" (as Administrator)
echo.
echo  Note: as a service the agent cannot lock the screen (Windows does not allow
echo  that from a service). Use run_agent.bat instead if you need that action.
echo.
pause
exit /b 0

:copyfail
echo [ERROR] Could not copy files to %INSTALL_DIR%.
pause
exit /b 1

:svcfail
echo [ERROR] Could not create the service. Is another AiBoO service still being removed?
echo         Restart the PC and run install_service.bat again.
pause
exit /b 1
