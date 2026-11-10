#!/usr/bin/env bash
# ==============================================================================
# Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
# Turnkey Virtual Environment Provisioner for Kali Linux (ARM64 / x86_64)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-${SCRIPT_DIR}/venv}"
REQUIREMENTS_FILE="${SCRIPT_DIR}/detector/requirements-kali.txt"

echo "======================================================================"
echo "  🚀 Wi-Fi IDS v2.1.2 - Kali Linux Virtual Environment Setup"
echo "======================================================================"
echo "Target Directory : ${SCRIPT_DIR}"
echo "Venv Destination : ${VENV_DIR}"
echo "Python Version   : $(python3 --version 2>/dev/null || echo 'Not installed')"
echo "======================================================================"

# 1. Check & Install System Packages (if running as root or with sudo)
echo ""
echo "[Step 1/5] Checking Debian / Kali Linux System Prerequisites..."
MISSING_PKGS=()
for pkg in python3 python3-venv python3-pip python3-dev build-essential libpcap-dev wireless-tools; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "[*] Missing system packages detected: ${MISSING_PKGS[*]}"
    if [ "$(id -u)" -eq 0 ]; then
        echo "[*] Updating apt package lists and installing prerequisites..."
        apt-get update -y
        apt-get install -y --no-install-recommends "${MISSING_PKGS[@]}"
    elif command -v sudo >/dev/null 2>&1; then
        echo "[*] Prompting for sudo to install system packages..."
        sudo apt-get update -y
        sudo apt-get install -y --no-install-recommends "${MISSING_PKGS[@]}"
    else
        echo "[!] ERROR: System packages missing and cannot elevate with sudo."
        echo "    Please run manually: sudo apt-get install -y ${MISSING_PKGS[*]}"
        exit 1
    fi
else
    echo "[+] All required system packages are already installed."
fi

# 2. Create Python Virtual Environment (PEP 668 Compliant)
echo ""
echo "[Step 2/5] Initializing Python Virtual Environment (venv)..."
if [ -d "${VENV_DIR}" ]; then
    echo "[*] Existing venv found at ${VENV_DIR}. Re-using..."
else
    python3 -m venv "${VENV_DIR}"
    echo "[+] Virtual environment created successfully at: ${VENV_DIR}"
fi

# 3. Upgrade pip and install Python packages inside venv
echo ""
echo "[Step 3/5] Installing Python Dependencies inside venv..."
"${VENV_DIR}/bin/python3" -m pip install --upgrade pip setuptools wheel

if [ ! -f "${REQUIREMENTS_FILE}" ]; then
    echo "[!] ERROR: Requirements file not found at ${REQUIREMENTS_FILE}"
    exit 1
fi

"${VENV_DIR}/bin/python3" -m pip install -r "${REQUIREMENTS_FILE}"
echo "[+] All Python packages installed successfully inside venv."

# 4. Pre-download Edge ML Model Weights into local cache
echo ""
echo "[Step 4/5] Pre-warming FastEmbed Edge Embeddings (BAAI/bge-small-en-v1.5)..."
"${VENV_DIR}/bin/python3" -c "
from fastembed import TextEmbedding
print('[*] Caching BAAI/bge-small-en-v1.5 weights locally...')
m = TextEmbedding('BAAI/bge-small-en-v1.5')
vec = list(m.embed(['Prewarm_Cache']))[0]
print(f'[+] Model successfully cached! Vector dimension: {len(vec)}')
"

# 5. Run Health Check & Self-Test
echo ""
echo "[Step 5/5] Executing System Health Check & Pipeline Verification..."
PYTHONPATH="${SCRIPT_DIR}" "${VENV_DIR}/bin/python3" "${SCRIPT_DIR}/detector/validate_kali_env.py"

echo ""
echo "======================================================================"
echo "  🎉 KALI VIRTUAL ENVIRONMENT IS FULLY DEPLOYED AND READY!"
echo "======================================================================"
echo "To activate the environment:"
echo "    source ${VENV_DIR}/bin/activate"
echo ""
echo "To start the IDS Service in UDP Lab Mode:"
echo "    ./run_kali_ids.sh --mode udp"
echo ""
echo "To start the IDS Service in Live Monitor Sniffing Mode (e.g. wlan0mon):"
echo "    sudo ./run_kali_ids.sh --mode live --interface wlan0mon"
echo "======================================================================"
