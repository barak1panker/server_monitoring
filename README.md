# 🖥️ Server Monitoring Project

This project provides a lightweight server and endpoint monitoring system. It consists of a **Python Agent** that collects system information from endpoints and a **FastAPI server** that stores the logs in a PostgreSQL database, keeps JSON snapshots on disk, and exposes metrics for dashboards.

---

## ✨ Features

* **Agent (Python, Windows):**

  * Collects system details: hostname, MAC address, OS platform.
  * Captures running processes, active network connections, and connected USB devices.
  * Supports optional **file hashing** for selected directories.
  * Sends collected data as JSON to the server via `POST /collect-data`.
  * Test mode with `--once` for one-time submission (`test_agent.py`).

* **Server (FastAPI):**

  * `POST /collect-data`: receives and stores agent data in the database.
  * Stores a JSON snapshot on disk and saves the file path in the database (`json_path`).
  * `GET /api/metrics`: returns the latest metrics for dashboards (including calculated network rates).
  * Includes **CORS** support for local dashboard testing.

* **Database (PostgreSQL):**

  * Logs are stored with both structured fields and a JSON file path reference.

---

## 📂 Project Structure

```
SERVER_MONITORING/
├─ agent/
│  ├─ agent_updated.py      # Agent for collecting and sending data
│  ├─ run_agent.sh          # Script for running the agent in Linux
│  ├─ requirements.txt
│  └─ Dockerfile
│
├─ APP/
│  ├─ server.py             # FastAPI server implementation
│  ├─ requirements.txt
│  ├─ Dockerfile
│  └─ static/
│     └─ index.html         # Example static dashboard page
│
├─ test_agent.py            # Manual test agent script
├─ docker-compose.yml       # Compose file for API + PostgreSQL
├─ logs.db                  # SQLite/DB file (optional for local testing)
├─ .env                     # Environment variables
└─ README.md
```

---

## ⚙️ Environment Variables

Create a `.env` file for the server:

```
# .env (server)
DATABASE_URL=postgresql+psycopg2://monitor_user:monitor_pass@db:5432/monitor_db
LOGS_DIR=./logs_json
```

Agent configuration (either `.env` in `agent/` or CLI flags):

```
SERVER_URL=http://localhost:8000
HASHING_ENABLED=true
HASH_DIRS=C:\\Users\\barak
METRICS_INTERVAL=5
```

---

## 🗄️ Database Schema — Logs Table

| Column       | Type      | Description                     |
| ------------ | --------- | ------------------------------- |
| id           | SERIAL PK | Unique identifier               |
| hostname     | TEXT      | Endpoint hostname               |
| mac\_address | TEXT      | MAC address                     |
| platform     | TEXT      | Operating system string         |
| processes    | JSONB     | List of collected processes     |
| connections  | JSONB     | Active network connections      |
| usb\_devices | JSONB     | Connected USB devices           |
| json\_path   | TEXT      | File path of saved JSON log     |
| created\_at  | TIMESTAMP | Timestamp when log was inserted |

---

## ▶️ Running in Development

**Start the server:**

```bash
cd APP
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

**Run the agent:**

```bash
cd agent
python agent_updated.py --server http://localhost:8000

# One-time test run
python ../test_agent.py --server http://localhost:8000 --once
```

---

## 🐳 Docker Setup

```bash
docker compose up -d --build
```

* API available at `http://localhost:8000`
* PostgreSQL exposed on port `5432`
* Optional: pgAdmin available on port `8081`

---

## 🌐 API Endpoints

* `POST /collect-data`

  * Accepts JSON from the agent, stores it in the database, saves JSON on disk.
* `GET /api/metrics`

  * Returns the latest metrics in a dashboard-friendly format.

---

## 🧪 Quick Tests

```bash
# Check server status
curl http://localhost:8000/api/metrics

# Submit sample payload
curl -X POST http://localhost:8000/collect-data \
  -H "Content-Type: application/json" \
  -d '{"hostname":"WIN-01","mac_address":"00:11:22:33:44:55","platform":"Windows-10","processes":[],"connections":[],"usb_devices":[]}'
```

---

## 📌 Roadmap

* [x] Save JSON logs to disk and track path in DB.
* [ ] Add endpoint for filtered log queries.
* [ ] Baseline rules (YAML) for anomaly detection.
* [ ] Package agent as Windows EXE + scheduling.

---

## 👤 Author

Developed by **Barak Penker**
IT & Systems / Python
