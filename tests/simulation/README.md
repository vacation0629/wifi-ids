# Virtual Wi-Fi Simulation Lab (Dev & Automated Test Harness)

This directory contains containerized and script-based 802.11 virtual packet generators used for developer testing without physical Wi-Fi hardware:

## Files in this Directory
- `docker-compose.yml`: Original multi-container lab (spawns 4 Alpine Scapy generators).
- `docker-compose.consolidated.yml`: High-efficiency single-container generator running 4 concurrent threads.
- `clients/`: Python and Scapy packet synthesis scripts (`unified_traffic_simulator.py`).

## Usage
These simulations broadcast synthetic 802.11 Beacon, Probe, and Deauth frames over UDP port 5555 to verify pipeline parsing and dashboard alerts.

For physical real-world operations on Kali Linux or Raspberry Pi, use **Kismet** (`kismet_connector.py`) instead of virtual simulation.
