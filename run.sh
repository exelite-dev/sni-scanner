#!/usr/bin/env bash
# Vortex SNI Hunter Pro - Linux / macOS Launcher
cd "$(dirname "$0")"

echo "========================================================"
echo "       ⚡️ V O R T E X   S N I   H U N T E R   P R O"
echo "              Universal VLESS Reality Scanner"
echo "========================================================"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    exit 1
fi

python3 -c "import fastapi, uvicorn, aiohttp, dnspython" &> /dev/null
if [ $? -ne 0 ]; then
    echo "[INFO] Installing dependencies..."
    pip3 install -r requirements.txt
fi

echo "[INFO] Starting Web Dashboard at http://127.0.0.1:8787 ..."
python3 -m uvicorn web.app:app --host 0.0.0.0 --port 8787
