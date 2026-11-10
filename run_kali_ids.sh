#!/usr/bin/env bash
# ==============================================================================
# Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
# Production Service Launcher for Kali Linux
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find Virtual Environment
VENV_CANDIDATES=(
    "${SCRIPT_DIR}/venv"
    "/app/venv"
    "${HOME}/.ids_v2_venv"
)

ACTIVE_VENV=""
for candidate in "${VENV_CANDIDATES[@]}"; do
    if [ -f "${candidate}/bin/activate" ]; then
        ACTIVE_VENV="${candidate}"
        break
    fi
done

if [ -n "${ACTIVE_VENV}" ]; then
    echo "[*] Activating virtual environment: ${ACTIVE_VENV}"
    source "${ACTIVE_VENV}/bin/activate"
else
    echo "[!] Warning: No virtual environment found in standard paths."
    echo "    If dependencies are missing, run: ./setup_kali_venv.sh"
fi

export PYTHONPATH="${SCRIPT_DIR}:${SCRIPT_DIR}/detector:${PYTHONPATH}"

# Execute Kali IDS Daemon
exec python3 "${SCRIPT_DIR}/detector/kali_ids_service.py" "$@"
