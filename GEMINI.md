# 🚨 AGENT OPERATIONAL RULES & POLICIES (MANDATORY)

> **CRITICAL DIRECTIVE FOR ALL AGENTS (Antigravity, Gemini, Claude, Cursor, etc.):**
> Read and strictly follow these rules before executing any commands or touching any services in this repository.

---

### 1. Docker Lifecycle & Resource Safety (ZERO DESTRUCTION POLICY)
* **NEVER RUN `docker compose down`:**
  * Do NOT run `docker compose down`, `docker rm`, `docker system prune`, or any command that removes/unregisters containers, networks, or volumes.
  * Running `docker compose down` destroys container registrations in Docker Desktop and is considered a **major red flag / violation**.
* **ALWAYS USE `docker compose stop`:**
  * When asked to "stop", "pause", "sleep", "shut down", or finish a session, **ONLY** run:
    ```bash
    docker compose stop
    ```
  * Containers must always remain registered, intact, and visible in Docker Desktop in an `Exited` / `Stopped` state.
* **RESTORE & RESUME:**
  * To start or resume services, always use:
    ```bash
    docker compose start
    # or: docker compose up -d (non-destructive)
    ```

---

### 2. Local AI & Model Files Safety
* **NEVER delete model weights or binaries:**
  * Files in `local_llm/models/` (`*.gguf`) and `local_llm/bin/` (`llama-server.exe`, Vulkan DLLs) take significant time and bandwidth to download. Never remove or overwrite them without explicit user consent.
* **NEVER wipe the database:**
  * `detector/wifi_records.db` contains real-world and simulated historical detection logs. Never delete or recreate it unless explicitly commanded.

---

### 3. Summary of Allowed vs Prohibited Commands

| User Intent | Allowed Command | STRICTLY FORBIDDEN |
| :--- | :--- | :--- |
| "Stop", "Pause", "Sleep", "Finish" | `docker compose stop` | ❌ `docker compose down`<br>❌ `docker rm`<br>❌ `docker compose down -v` |
| "Start", "Resume", "Run" | `docker compose start` or `docker compose up -d` | ❌ `docker compose up --force-recreate` |
| "Kill background server" | Graceful stop via task kill or task cancellation | ❌ Deleting executable/binaries |
