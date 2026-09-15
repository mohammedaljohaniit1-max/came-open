#!/usr/bin/env bash
# ================================================================
#  CAMRADAR - Attack Surface Intelligence Platform (Linux/macOS launcher)
# ================================================================
set -e

echo "================================================================"
echo "  CAMRADAR - OSINT Camera Aggregator & Availability Validator"
echo "================================================================"

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing dependencies..."
pip install -q -r requirements.txt

echo "[*] Launching CAMRADAR on http://localhost:5000 ..."
python app.py
