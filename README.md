# Rogue WiFi / Evil Twin Detector (Low-RAM Raspberry Pi 4/5 + Cloud Nemotron)

A lightweight Rogue Access Point (Evil Twin) detection architecture designed to run on resource-constrained devices like the **Raspberry Pi 4 / Pi 5 (ARM64)**, with PC simulation via Docker.

---

## 1. Architecture & RAM Optimization

Running a 4B–5B LLM directly on a Raspberry Pi consumes 4–8 GB of RAM and overwhelms device resources. This architecture offloads inference to cloud endpoints while keeping local workloads ultra-lightweight.

```
+-------------------------------------------------------------------+
|               Raspberry Pi 4 / 5 or Kali ARM Container            |
|  [detector.py]                                                    |
|  - RAM Usage: < 25 MB                                             |
|  - Pure Python Cosine Similarity & N-Gram pre-filter              |
|  - Reads Whitelist (whitelist.json)                               |
+------------------+------------------------------------------------+
                   |
                   | HTTPS REST API (Token-authenticated)
                   v
+-------------------------------------------------------------------+
|               Hugging Face Cloud Serverless API                   |
|  1. Embedding Endpoint (sentence-transformers / NV-Embed)        |
|  2. nvidia/nemotron-mini-4b-instruct (Evil Twin Validation)       |
+-------------------------------------------------------------------+
```

---

## 2. PC Simulation Lab (Ultra-Low RAM 802.11 Wi-Fi Frame Simulation)

The client nodes do **not** need to be Kali Linux. To keep RAM usage minimal:
- **Clients**: Ultra-lightweight **Alpine Linux** containers running Scapy (`wifi-frame-client`).
- **Memory per Client**: Capped at **45 MB RAM**.
- **Frame Types**:
  - `client-rogue-ap`: Emits real IEEE 802.11 **Beacon** frames with typo-squatted & homoglyph SSIDs (e.g. `Company_Official-5G`, `Company_Officia1_5G`).
  - `client-authorized-ap`: Emits real IEEE 802.11 **Beacon** frames with whitelisted SSIDs.
  - `client-probe-station`: Emits IEEE 802.11 **Probe Request** frames.
- **Detector**: Listens for raw 802.11 frames, extracts the SSID from Information Element (IE 0), and computes cosine similarity against the authorized whitelist.

### Start the Lab:
```powershell
docker compose up --build
```

### View Live Detector Logs:
```powershell
docker compose logs -f kali-detector
```

### Stop the Lab:
```powershell
docker compose down
```

---

## 3. Configuration

1. Copy `.env.example` to `.env`:
   ```powershell
   cp .env.example .env
   ```
2. Insert your [Hugging Face User Access Token](https://huggingface.co/settings/tokens):
   ```env
   HF_API_TOKEN=hf_xxxxxxxxxxxxxxxxx
   ```
3. Customize authorized networks in `detector/whitelist.json`:
   ```json
   [
     "Company_Official_5G",
     "Company_Staff_Secure",
     "Company_Guest_WiFi"
   ]
   ```

---

## 4. Deploying to Raspberry Pi 4 / 5

On the physical Raspberry Pi:

1. Clone or copy this repository to the Pi:
   ```bash
   git clone <repo_url>
   cd "Rogue wifi"
   ```
2. Install minimal dependencies (no PyTorch or heavy libraries required):
   ```bash
   pip3 install -r detector/requirements.txt
   ```
3. Run the detector:
   ```bash
   python3 detector/detector.py
   ```
