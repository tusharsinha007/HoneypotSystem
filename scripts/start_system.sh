#!/bin/bash
# LLMPot — Start System (Linux/macOS)
set -e

cd "$(dirname "$0")/.."

echo "🍯 LLMPot System Launcher"
echo "═══════════════════════════"

# Generate key if needed
if [ ! -f "keys/host_key" ]; then
    echo "[*] Generating SSH host key..."
    python3 generate_key.py
fi

# Initialize if needed
if [ ! -f "models/kmeans_model.joblib" ]; then
    echo "[*] Generating training data..."
    python3 training/generate_dataset.py -n 500
    echo "[*] Training ML model..."
    python3 training/train.py
fi

echo "[*] Starting honeypot server..."
python3 main.py
