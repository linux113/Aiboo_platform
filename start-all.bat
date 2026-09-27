@echo off
title AiBoO Platform Launcher
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo ============================================
echo   AiBoO Tri-Gate Defense Platform
echo ============================================
echo.

if not exist "logs" mkdir logs
if exist ".pids.txt" del /f .pids.txt

REM ---- Resolve Python ----
set PYTHON_CMD=python
py -3 --version >nul 2>&1
if %ERRORLEVEL% EQU 0 set PYTHON_CMD=py -3

REM ---- Check MongoDB ----
echo [1/5] Checking MongoDB...
set MONGO_OK=0
for /f "tokens=2" %%a in ('netstat -an 2^>nul ^| findstr /C:":27017"') do (
    echo %%a | findstr /i "LISTEN" >nul && set MONGO_OK=1
)
if "%MONGO_OK%"=="0" (
    echo   [WARN] MongoDB not detected on port 27017
    echo   Backend may not start until MongoDB is running.
    echo   Start it: net start MongoDB
    echo.
) else (
    echo   [OK] MongoDB running
    echo.
)

REM ---- Start Backend ----
echo [2/5] Starting Backend (port 4000)...
start "AiBoO-Backend" cmd /c "title AiBoO Backend && cd /d %~dp0backend && node server.js > %~dp0logs\backend.log 2>&1"
timeout /t 3 >nul

set WAIT=0
:WAIT_BACKEND
timeout /t 2 >nul
set /a WAIT+=1
powershell -Command "try{$r=Invoke-WebRequest 'http://localhost:4000/health' -UseBasicParsing -TimeoutSec 2;exit 0}catch{exit 1}" >nul 2>&1
if errorlevel 1 (
    if !WAIT! GEQ 12 (
        echo   [WARN] Backend not ready (timeout). Check logs\backend.log
        goto SKIP_BACKEND
    )
    goto WAIT_BACKEND
)
echo   [OK] Backend healthy
:SKIP_BACKEND
echo.

REM ---- Start Frontend ----
echo [3/5] Starting Frontend (port 3000)...
start "AiBoO-Frontend" cmd /c "title AiBoO Frontend && cd /d %~dp0frontend && npx vite --host 0.0.0.0 --port 3000 > %~dp0logs\frontend.log 2>&1"
timeout /t 4 >nul

set WAIT=0
:WAIT_FRONTEND
timeout /t 2 >nul
set /a WAIT+=1
powershell -Command "try{$r=Invoke-WebRequest 'http://localhost:3000' -UseBasicParsing -TimeoutSec 2;exit 0}catch{exit 1}" >nul 2>&1
if errorlevel 1 (
    if !WAIT! GEQ 8 (
        echo   [WARN] Frontend not ready (timeout). Check logs\frontend.log
        goto SKIP_FRONTEND
    )
    goto WAIT_FRONTEND
)
echo   [OK] Frontend ready
:SKIP_FRONTEND
echo.

REM ---- Start CV Service ----
echo [4/5] Starting CV Service (port 5050)...
start "AiBoO-CV" cmd /c "title AiBoO CV && cd /d %~dp0cv-service && %PYTHON_CMD% app.py > %~dp0logs\cv-service.log 2>&1"
timeout /t 5 >nul

set WAIT=0
:WAIT_CV
timeout /t 2 >nul
set /a WAIT+=1
powershell -Command "try{$r=Invoke-WebRequest 'http://localhost:5050/health' -UseBasicParsing -TimeoutSec 2;exit 0}catch{exit 1}" >nul 2>&1
if errorlevel 1 (
    if !WAIT! GEQ 10 (
        echo   [WARN] CV Service not ready (timeout). Check logs\cv-service.log
        goto SKIP_CV
    )
    goto WAIT_CV
)
echo   [OK] CV Service healthy
:SKIP_CV
echo.

REM ---- Start Agent ----
echo [5/5] Starting Agent (port 8001)...
start "AiBoO-Agent" cmd /c "title AiBoO Agent && cd /d %~dp0agent && %PYTHON_CMD% main.py > %~dp0logs\agent.log 2>&1"
timeout /t 5 >nul

set WAIT=0
:WAIT_AGENT
timeout /t 2 >nul
set /a WAIT+=1
powershell -Command "try{$r=Invoke-WebRequest 'http://localhost:8001/health' -UseBasicParsing -TimeoutSec 2;exit 0}catch{exit 1}" >nul 2>&1
if errorlevel 1 (
    if !WAIT! GEQ 8 (
        echo   [WARN] Agent not ready (timeout). Check logs\agent.log
        goto SKIP_AGENT
    )
    goto WAIT_AGENT
)
echo   [OK] Agent healthy
:SKIP_AGENT

echo.
echo ============================================
echo   AiBoO is running!
echo   Dashboard: http://localhost:3000
echo   Backend:   http://localhost:4000
echo   Agent API: http://localhost:8001
echo   CV Service: http://localhost:5050
echo.
echo   To stop: run close-all.bat or close this window
echo.

:WAIT_LOOP
timeout /t 10 /nobreak >nul
goto WAIT_LOOP
