#!/bin/bash
# LLMPot — Dashboard Launcher (Linux/macOS)
cd "$(dirname "$0")/.."
echo "[*] Starting LLMPot Dashboard..."
streamlit run dashboard/app.py --server.port=8501
