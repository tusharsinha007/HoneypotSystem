@echo off
REM LLMPot — Next-Gen Dashboard Launcher (Windows)
echo [*] Starting LLMPot SOC Next-Gen Dashboard...
cd /d "%~dp0..\dashboard-next"

echo [*] Starting Python HTTP Server on port 8000...
start http://localhost:8000
python -m http.server 8000
