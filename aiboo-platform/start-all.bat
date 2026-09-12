@echo off
title AiBoO Platform Launcher
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

REM ==================================================
REM  AiBoO Tri-Gate Defense Platform - Smart Launcher
REM  - auto-installs missing dependencies
REM  - seeds agent\config.ini (no interactive prompt)
REM  - longer health waits, prints log tails on failure
REM ==================================================

REM ---- User settings (change here if needed) ----
set "BACKEND_URL=http://localhost:4000"
set "AGENT_API_KEY=dev-key-change-in-production"

set "STATUS_BACKEND=DOWN"
set "STATUS_FRONTEND=DOWN"
set "STATUS_CV=DOWN"
set "STATUS_AGENT=DOWN"

echo ============================================
echo   AiBoO Tri-Gate Defense Platform
echo ============================================
echo.

if not exist "logs" mkdir "logs"
if exist ".pids.txt" del /f /q ".pids.txt"

REM ---- Resolve Python command ----
set "PYTHON_CMD=python"
py -3 --version >nul 2>&1
if not errorlevel 1 set "PYTHON_CMD=py -3"

REM ==================================================
REM [0/6] Install missing dependencies
REM ==================================================
echo [0/6] Checking dependencies...

if not exist "backend\node_modules\" (
    echo   - Installing backend npm packages...
    pushd backend
    call npm install --no-audit --no-fund --loglevel=error
    popd
)

if not exist "frontend\node_modules\" (
    echo   - Installing frontend npm packages...
    pushd frontend
    call npm install --no-audit --no-fund --loglevel=error
    popd
)

%PYTHON_CMD% -c "import fastapi, uvicorn, psutil, httpx, cachetools, pydantic" >nul 2>&1
if errorlevel 1 (
    echo   - Installing agent Python packages...
    %PYTHON_CMD% -m pip install -q -r agent\requirements.txt
)

%PYTHON_CMD% -c "import flask, cv2, ultralytics" >nul 2>&1
if errorlevel 1 (
    echo   - CV service packages missing. They are heavy ~2 GB, PyTorch-based.
    choice /C YN /T 20 /D N /M "   Install CV packages now"
    if not errorlevel 2 (
        echo   - Installing CV packages, please wait several minutes...
        %PYTHON_CMD% -m pip install -q -r cv-service\requirements.txt
    ) else (
        echo   [SKIP] CV service will fail to start. Install later with:
        echo          %PYTHON_CMD% -m pip install -r cv-service\requirements.txt
    )
)

echo   [OK] Dependencies ready
echo.

REM ==================================================
REM [1/6] Check MongoDB
REM ==================================================
echo [1/6] Checking MongoDB...

powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 27017 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }"

if errorlevel 1 (
    echo   [WARN] MongoDB not detected on port 27017
    echo   Backend will fail to connect. Start it: net start MongoDB
) else (
    echo   [OK] MongoDB running
)
echo.

REM ==================================================
REM [2/6] Start Backend  (skip if already up)
REM ==================================================
echo [2/6] Starting Backend (port 4000)...

powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 4000 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Already running on port 4000
    set "STATUS_BACKEND=UP-existing"
    goto MONGO_HINT
)

if not exist "backend\server.js" (
    echo   [ERROR] backend\server.js not found
    goto MONGO_HINT
)

start "AiBoO Backend" cmd /c "cd /d ""%~dp0backend"" && node server.js > ""%~dp0logs\backend.log"" 2>&1"

set WAIT=0
:WAIT_BACKEND
timeout /t 2 /nobreak >nul
set /a WAIT+=1
powershell -NoProfile -Command "try { Invoke-WebRequest 'http://127.0.0.1:4000/health' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Backend healthy
    set "STATUS_BACKEND=UP"
    goto MONGO_HINT
)
if !WAIT! GEQ 15 goto BACKEND_TIMEOUT
goto WAIT_BACKEND

:BACKEND_TIMEOUT
echo   [WARN] Backend not ready. Last log lines:
powershell -NoProfile -Command "Get-Content -Path 'logs\backend.log' -Tail 8 -ErrorAction SilentlyContinue"

:MONGO_HINT
if "!STATUS_BACKEND!"=="DOWN" goto AFTER_HINT
REM ---- Hint if the default admin user is missing ----
powershell -NoProfile -Command "try { Invoke-WebRequest 'http://127.0.0.1:4000/api/auth/login' -Method POST -Body '{\"email\":\"admin@example.com\",\"password\":\"admin123\"}' -ContentType 'application/json' -UseBasicParsing -TimeoutSec 3 | Out-Null; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo   [HINT] Default admin login not found - run once:  cd backend ^&^& node seed.js
)
:AFTER_HINT
echo.

REM ==================================================
REM [3/6] Start Frontend  (skip if already up)
REM ==================================================
echo [3/6] Starting Frontend (port 3000)...

powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 3000 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Already running on port 3000
    set "STATUS_FRONTEND=UP-existing"
    goto SKIP_FRONTEND
)

if not exist "frontend\package.json" (
    echo   [ERROR] frontend folder/package.json not found
    goto SKIP_FRONTEND
)

start "AiBoO Frontend" cmd /c "cd /d ""%~dp0frontend"" && npx vite --host 0.0.0.0 --port 3000 > ""%~dp0logs\frontend.log"" 2>&1"

set WAIT=0
:WAIT_FRONTEND
timeout /t 2 /nobreak >nul
set /a WAIT+=1
powershell -NoProfile -Command "try { Invoke-WebRequest 'http://127.0.0.1:3000/' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Frontend ready
    set "STATUS_FRONTEND=UP"
    goto SKIP_FRONTEND
)
if !WAIT! GEQ 20 goto FRONTEND_TIMEOUT
goto WAIT_FRONTEND

:FRONTEND_TIMEOUT
echo   [WARN] Frontend not ready. Last log lines:
powershell -NoProfile -Command "Get-Content -Path 'logs\frontend.log' -Tail 8 -ErrorAction SilentlyContinue"

:SKIP_FRONTEND
echo.

REM ==================================================
REM [4/6] Start CV Service  (optional, skip if already up)
REM ==================================================
echo [4/6] Starting CV Service (port 5050)...

powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 5050 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Already running on port 5050
    set "STATUS_CV=UP-existing"
    goto SKIP_CV
)

if not exist "cv-service\app.py" (
    echo   [WARN] cv-service\app.py not found - skipping
    goto SKIP_CV
)

start "AiBoO CV" cmd /c "cd /d ""%~dp0cv-service"" && set PYTHONUNBUFFERED=1 && %PYTHON_CMD% app.py > ""%~dp0logs\cv-service.log"" 2>&1"

echo   - Waiting (first run downloads the YOLO model, be patient)...
set WAIT=0
:WAIT_CV
timeout /t 2 /nobreak >nul
set /a WAIT+=1
powershell -NoProfile -Command "try { Invoke-WebRequest 'http://127.0.0.1:5050/health' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if not errorlevel 1 (
    echo   [OK] CV Service healthy
    set "STATUS_CV=UP"
    goto SKIP_CV
)
if !WAIT! GEQ 45 goto CV_TIMEOUT
goto WAIT_CV

:CV_TIMEOUT
echo   [WARN] CV Service not ready - it is OPTIONAL. Last log lines:
powershell -NoProfile -Command "Get-Content -Path 'logs\cv-service.log' -Tail 8 -ErrorAction SilentlyContinue"

:SKIP_CV
echo.

REM ==================================================
REM [5/6] Seed agent config (prevents interactive prompt)
REM ==================================================
echo [5/6] Checking agent configuration...

if not exist "agent\config.ini" (
    (
        echo [AIBOO]
        echo remote_url = %BACKEND_URL%
        echo api_key = %AGENT_API_KEY%
        echo endpoint_name = %COMPUTERNAME%
        echo server_ip = 192.168.1.100
        echo log_level = INFO
    ) > "agent\config.ini"
    echo   [OK] Created agent\config.ini - endpoint name: %COMPUTERNAME%
) else (
    echo   [OK] agent\config.ini exists
)

REM ==================================================
REM [6/6] Start Agent  (skip if already up)
REM ==================================================
echo [6/6] Starting Agent (port 8001)...

powershell -NoProfile -Command "if ((Test-NetConnection 127.0.0.1 -Port 8001 -WarningAction SilentlyContinue).TcpTestSucceeded) { exit 0 } else { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Already running on port 8001
    set "STATUS_AGENT=UP-existing"
    goto FINAL_SUMMARY
)

if not exist "agent\main.py" (
    echo   [ERROR] agent\main.py not found
    goto FINAL_SUMMARY
)

start "AiBoO Agent" cmd /c "cd /d ""%~dp0agent"" && set PYTHONUNBUFFERED=1 && %PYTHON_CMD% main.py > ""%~dp0logs\agent.log"" 2>&1"

set WAIT=0
:WAIT_AGENT
timeout /t 2 /nobreak >nul
set /a WAIT+=1
powershell -NoProfile -Command "try { Invoke-WebRequest 'http://127.0.0.1:8001/health' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if not errorlevel 1 (
    echo   [OK] Agent healthy
    set "STATUS_AGENT=UP"
    goto FINAL_SUMMARY
)
if !WAIT! GEQ 20 goto AGENT_TIMEOUT
goto WAIT_AGENT

:AGENT_TIMEOUT
echo   [WARN] Agent not ready. Last log lines:
powershell -NoProfile -Command "Get-Content -Path 'logs\agent.log' -Tail 8 -ErrorAction SilentlyContinue"

:FINAL_SUMMARY
echo.
echo ============================================
echo   AiBoO Status
echo ============================================
echo   Backend   :4000  - !STATUS_BACKEND!
echo   Frontend  :3000  - !STATUS_FRONTEND!
echo   CV Service:5050  - !STATUS_CV!   ^(optional^)
echo   Agent     :8001  - !STATUS_AGENT!
echo.
echo   Dashboard : http://localhost:3000
echo   Login     : admin@example.com / admin123   ^(after seed.js^)
echo.
echo   Logs      : .\logs\
echo   Stop all  : close-all.bat
echo ============================================
echo.

:WAIT_LOOP
timeout /t 30 /nobreak >nul
goto WAIT_LOOP
