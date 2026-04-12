@echo off
REM LLMPot — Dashboard Launcher (Windows)
echo [*] Starting LLMPot Dashboard...
cd /d "%~dp0.."
streamlit run dashboard\app.py --server.port=8501
