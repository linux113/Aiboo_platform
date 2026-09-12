@echo off
echo Stopping all AiBoO services...
taskkill /FI "WINDOWTITLE eq AiBoO Backend" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO Frontend" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO CV" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AiBoO Agent" /F >nul 2>&1
echo All AiBoO services stopped.
timeout /t 2 >nul
