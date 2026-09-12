@echo off
title AiBoO Platform Setup
setlocal enabledelayedexpansion

echo ============================================
echo   AiBoO - Installing Dependencies
echo ============================================
echo.

REM ---- Check required tools ----
echo Checking prerequisites...
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 echo [ERROR] node not found in PATH. Install Node.js from https://nodejs.org && pause && exit /b 1

where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 echo [ERROR] npm not found in PATH. && pause && exit /b 1

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    where py >nul 2>&1
    if !ERRORLEVEL! NEQ 0 echo [ERROR] python not found in PATH. Install Python from https://python.org && pause && exit /b 1
)

pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    python -m pip --version >nul 2>&1
    if !ERRORLEVEL! NEQ 0 echo [ERROR] pip not found. && pause && exit /b 1
)
echo   All prerequisites found.
echo.

REM ---- [1/4] Backend dependencies ----
echo [1/4] Backend dependencies...
cd /d "%~dp0backend"
if not exist "node_modules" (
    if exist "package-lock.json" (
        npm ci
    ) else (
        npm install
    )
    if %ERRORLEVEL% NEQ 0 echo [ERROR] Backend npm install failed. && pause && exit /b 1
    echo   Backend dependencies installed.
) else (
    echo   Already installed.
)

echo.
REM ---- [2/4] Frontend dependencies ----
echo [2/4] Frontend dependencies...
cd /d "%~dp0frontend"
if not exist "node_modules" (
    if exist "package-lock.json" (
        npm ci
    ) else (
        npm install
    )
    if %ERRORLEVEL% NEQ 0 echo [ERROR] Frontend npm install failed. && pause && exit /b 1
    echo   Frontend dependencies installed.
) else (
    echo   Already installed.
)

echo.
REM ---- [3/4] Python agent dependencies ----
echo [3/4] Python agent dependencies...
cd /d "%~dp0agent"
if not exist "requirements.txt" echo [ERROR] agent\requirements.txt not found. && pause && exit /b 1
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 echo [ERROR] Agent pip install failed. && pause && exit /b 1
echo   Done.

echo.
REM ---- [4/4] Python CV dependencies ----
echo [4/4] Python CV dependencies...
cd /d "%~dp0cv-service"
if not exist "requirements.txt" echo [ERROR] cv-service\requirements.txt not found. && pause && exit /b 1
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 echo [ERROR] CV service pip install failed. && pause && exit /b 1
echo   Done.

echo.
echo ============================================
echo   Setup complete! Run start-all.bat to launch.
echo ============================================
pause
