@echo off
REM ═══════════════════════════════════════════
REM  LLMPot — Start System (Windows)
REM ═══════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║        🍯 LLMPot Launcher                ║
echo  ╚══════════════════════════════════════════╝
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

cd /d "%~dp0.."

REM Generate key if needed
if not exist "keys\host_key" (
    echo [*] Generating SSH host key...
    python generate_key.py
)

REM Initialize DB and train if no model exists
if not exist "models\kmeans_model.joblib" (
    echo [*] Generating training data...
    python training\generate_dataset.py -n 500
    echo [*] Training ML model...
    python training\train.py
)

echo [*] Starting honeypot server...
echo [*] Press Ctrl+C to stop
echo.
python main.py
