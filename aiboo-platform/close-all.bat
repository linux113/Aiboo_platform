@echo off
title AiBoO - Stop All Services
echo Stopping all AiBoO services...

REM ---- Close launcher windows by title ----
taskkill /FI "WINDOWTITLE eq AiBoO Backend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO Frontend*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO CV*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO Agent*" /F >nul 2>&1

REM ---- Fallback: kill whatever is LISTENING on AiBoO ports (skips MongoDB 27017) ----
powershell -NoProfile -Command ^
  "4000,3000,5050,8001 | ForEach-Object { $p = $_; Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { try { Stop-Process -Id $_ -Force -ErrorAction Stop; Write-Host ('  killed PID ' + $_ + ' on port ' + $p) } catch {} } }" >nul 2>&1

echo All AiBoO services stopped.
timeout /t 2 >nul
