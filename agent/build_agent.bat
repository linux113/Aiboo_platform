@echo off
setlocal EnableExtensions
title AiBoO Agent - build AiBoO-Agent.exe and dist.zip
cd /d "%~dp0"

echo ==========================================================
echo   AiBoO Agent - compile to AiBoO-Agent.exe + make dist.zip
echo ==========================================================
echo   Run this on a WINDOWS PC that has Python 3.10 or newer.
echo   Takes 3-10 minutes the first time - internet needed.
echo.

echo [1/6] Checking Python...
where python >nul 2>&1
if errorlevel 1 goto :nopython
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 goto :oldpython
python --version

echo [2/6] Build environment .buildenv - separate from your normal Python...
if not exist ".buildenv\Scripts\python.exe" (
    python -m venv .buildenv
    if errorlevel 1 goto :fail
)
set "PY=%~dp0.buildenv\Scripts\python.exe"

echo [3/6] Installing packages - requirements.txt + PyInstaller...
"%PY%" -m pip install --upgrade pip --quiet
"%PY%" -m pip install -r requirements.txt pyinstaller --quiet
if errorlevel 1 goto :fail

echo [4/6] Compiling AiBoO-Agent.exe - this is the slow part...
if exist "build\AiBoO-Agent" rmdir /s /q "build\AiBoO-Agent"
if exist "dist\AiBoO-Agent.exe" del /q "dist\AiBoO-Agent.exe"
"%PY%" -m PyInstaller --noconfirm --clean AiBoO-Agent.spec
if errorlevel 1 goto :fail
if not exist "dist\AiBoO-Agent.exe" goto :fail

echo [5/6] Putting the package together in dist\AiBoO-Agent ...
set "PKG=dist\AiBoO-Agent"
if exist "%PKG%" rmdir /s /q "%PKG%"
mkdir "%PKG%"
mkdir "%PKG%\config"
copy /Y "dist\AiBoO-Agent.exe" "%PKG%\" >nul
copy /Y "installer\config.template.ini" "%PKG%\config.ini" >nul
copy /Y "installer\config.template.ini" "%PKG%\" >nul
copy /Y "installer\configure.ps1" "%PKG%\" >nul
copy /Y "installer\install_service.bat" "%PKG%\" >nul
copy /Y "installer\uninstall_service.bat" "%PKG%\" >nul
copy /Y "installer\run_agent.bat" "%PKG%\" >nul
copy /Y "installer\stop_agent.bat" "%PKG%\" >nul
copy /Y "installer\show_status.bat" "%PKG%\" >nul
copy /Y "installer\nssm.exe" "%PKG%\" >nul
copy /Y "installer\README.txt" "%PKG%\" >nul
copy /Y "config\event_rules.yaml" "%PKG%\config\" >nul
copy /Y "config\ip_blocklist.txt" "%PKG%\config\" >nul

echo [6/6] Making dist.zip ...
if exist "dist.zip" del /q "dist.zip"
powershell -NoProfile -Command "Compress-Archive -Path 'dist\AiBoO-Agent' -DestinationPath 'dist.zip' -Force"
if errorlevel 1 goto :fail

echo.
echo ==========================================================
echo   DONE
echo ==========================================================
echo   %~dp0dist.zip
echo.
echo   On that PC, in the AiBoO-Agent folder:
echo     run_agent.bat    - right-click - "Run as administrator"
echo                        asks for the server address ONCE, then the agent
echo                        runs in the BACKGROUND - no window is left open.
echo     show_status.bat  - is it running and connected?  (log shown)
echo     stop_agent.bat   - stop the background agent.
echo     install_service.bat - always on from Windows start, also no window.
echo.
pause
exit /b 0

:nopython
echo [ERROR] Python is not installed or not in PATH.
echo         Install Python 3.12 from python.org and tick "Add python.exe to PATH".
pause
exit /b 1

:oldpython
echo [ERROR] Python 3.10 or newer is needed.
python --version
pause
exit /b 1

:fail
echo.
echo [ERROR] The build failed. Scroll up to the first red ERROR line and send a screenshot.
pause
exit /b 1
