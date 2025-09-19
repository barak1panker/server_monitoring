"""
Server Monitoring API — adapted to custom logs table:
logs(id, device_id, device_name, log_path, severity, created_at)

- Saves every incoming JSON (metrics & hashes) to disk and inserts a row into your logs table.
- severity values used: "METRICS" / "HASH".
- device_name = hostname from the agent; device_id left NULL (you can populate from the agent in the future).
- created_at stored as naive UTC (matches 'timestamp without time zone').

Other endpoints unchanged:
- POST /collect-metrics  -> updates in-memory cache (for /api/metrics), creates RESOURCE alerts on thresholds
- POST /collect-hashes   -> bulk insert file_hashes + compare to IOC table; creates HASH alerts on matches
- GET  /api/metrics      -> UI data
- GET  /api/alerts       -> latest alerts (for dashboard)
- GET  /api/logs         -> latest log rows from your 'logs' table
- POST /collect-data     -> compatibility alias to /collect-metrics
- GET  /health           -> health check
"""
from __future__ import annotations
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from pathlib import Path
from collections import deque
import os, json

# SQLAlchemy
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, DateTime, BigInteger,
    Float, select, desc, insert, UniqueConstraint, func
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import bindparam

# -------------------- FastAPI & static --------------------
app = FastAPI(title="Server Monitoring API", version="7.1.1")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "logs"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def index():
    idx = STATIC_DIR / "index.html"
    return FileResponse(idx) if idx.exists() else {"msg": "index.html not found"}

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time_utc": datetime.utcnow().isoformat() + "Z"}

# -------------------- DB setup --------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///logs.db")
engine = create_engine(DATABASE_URL, future=True)
metadata = MetaData()

IOC_SCHEMA = os.environ.get("IOC_SCHEMA", "public")
IOC_TABLE_NAME = os.environ.get("IOC_TABLE_NAME", "suspicious_hashes")
IOC_COL_SHA = os.environ.get("IOC_COL_SHA", "sha256")
IOC_FILE = os.environ.get("IOC_FILE", "/app/static/ioc_hashes.txt")
suspicious_hashes_set = set()

def load_ioc_hashes():
    global suspicious_hashes_set
    if os.path.exists(IOC_FILE):
        with open(IOC_FILE, "r") as f:
            suspicious_hashes_set = {line.strip().lower() for line in f if line.strip()}
        print(f"[INFO] Loaded {len(suspicious_hashes_set)} suspicious hashes from {IOC_FILE}")
    else:
        print(f"[WARNING] IOC file {IOC_FILE} not found")

load_ioc_hashes()

alerts = Table(
    "alerts", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("hostname", String(255), nullable=False),
    Column("category", String(32), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("label", String(64), nullable=False),
    Column("description", String(1024), nullable=False),
    Column("file_path", String(1024), nullable=True),
    Column("sha256", String(64), nullable=True),
    Column("cpu", Float, nullable=True),
    Column("ram_ratio", Float, nullable=True),
)

file_hashes = Table(
    "file_hashes", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("hostname", String(255), nullable=False),
    Column("file_path", String(1024), nullable=False),
    Column("sha256", String(64), nullable=True),
    Column("size", BigInteger, nullable=True),
    Column("mtime", DateTime(timezone=True), nullable=True),
    Column("error", String(512), nullable=True),
)

LOGS_TABLE_NAME = os.environ.get("LOGS_TABLE_NAME", "logs")
logs = Table(
    LOGS_TABLE_NAME, metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", Integer, nullable=True),
    Column("device_name", String(255), nullable=True),
    Column("log_path", String(1024), nullable=False),
    Column("severity", String(255), nullable=True),
    Column("created_at", DateTime(timezone=False), nullable=False),
)

if IOC_TABLE_NAME and IOC_TABLE_NAME != "suspicious_hashes":
    suspicious_hashes = Table(IOC_TABLE_NAME, metadata, schema=IOC_SCHEMA, autoload_with=engine)
    metadata.create_all(engine, tables=[alerts, file_hashes])
else:
    suspicious_hashes = Table(
        "suspicious_hashes", metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("sha256", String(64), nullable=False),
        Column("tag", String(128), nullable=True),
        Column("description", String(512), nullable=True),
        UniqueConstraint("sha256", name="uq_suspicious_sha256"),
    )
    metadata.create_all(engine)

CPU_HIGH = float(os.environ.get("CPU_HIGH", "80"))
RAM_RATIO_HIGH = float(os.environ.get("RAM_RATIO_HIGH", "0.8"))

# -------------------- helpers --------------------
def _utcnow_tz() -> datetime:
    return datetime.now(timezone.utc)

def _utcnow_naive() -> datetime:
    return datetime.utcnow()

def _parse_iso_to_aware(v: Optional[str]) -> Optional[datetime]:
    if not v: return None
    try:
        s = str(v)
        if s.endswith("Z"): s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _save_json_to_disk(data: dict) -> Tuple[str, datetime]:
    ts = _utcnow_tz()
    hn = (str(data.get("hostname") or "unknown")).replace(" ", "_")
    path = UPLOAD_DIR / f"{hn}_{ts.strftime('%Y-%m-%d_%H-%M-%S')}.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return str(path), ts

def _insert_alert(*, hostname: str, category: str, description: str,
                  severity: str = "CRITICAL", label: str = "Critical issue",
                  file_path: Optional[str] = None, sha256: Optional[str] = None,
                  cpu: Optional[float] = None, ram_ratio: Optional[float] = None) -> None:
    try:
        with engine.begin() as conn:
            if category == "HASH" and sha256:
                ts_24h_ago = _utcnow_tz() - timedelta(hours=24)
                dup_stmt = select(alerts.c.id).where(
                    (alerts.c.hostname == hostname) &
                    (alerts.c.sha256 == sha256) &
                    (alerts.c.category == "HASH") &
                    (alerts.c.ts >= ts_24h_ago)
                ).limit(1)
                dup = conn.execute(dup_stmt).first()
                if dup:
                    print(f"[Alert skipped] Duplicate hash alert for {sha256} on {hostname}")
                    return

            conn.execute(insert(alerts).values(
                ts=_utcnow_tz(), hostname=hostname, category=category, severity=severity,
                label=label, description=description[:1024],
                file_path=(file_path[:1024] if file_path else None),
                sha256=(sha256[:64] if sha256 else None),
                cpu=cpu, ram_ratio=ram_ratio
            ))
    except SQLAlchemyError as e:
        print(f"[DB] insert alert failed: {e}")

# -------------------- in-memory metrics cache --------------------
METRICS_HISTORY_LEN = 20
STALE_SECS = int(os.environ.get("METRICS_STALE_SECS", "30"))
_metrics_cache = {}
_history_up   = deque(maxlen=METRICS_HISTORY_LEN)
_history_down = deque(maxlen=METRICS_HISTORY_LEN)
_history_cpu  = deque(maxlen=METRICS_HISTORY_LEN)
_history_ram  = deque(maxlen=METRICS_HISTORY_LEN)

# -------------------- endpoints --------------------
@app.post("/collect-metrics")
async def collect_metrics(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    file_path, ts_aware = _save_json_to_disk(data)
    hostname = str(data.get("hostname") or "unknown")
    try:
        with engine.begin() as conn:
            conn.execute(insert(logs).values(
                device_id=None,
                device_name=hostname,
                log_path=file_path,
                severity="METRICS",
                created_at=_utcnow_naive(),
            ))
    except SQLAlchemyError as e:
        print("[DB] insert logs failed:", e)

    rt = float(data.get("ramTotal") or 0.0)
    ru = float(data.get("ramUsed") or 0.0)
    ram_ratio = (ru / rt) if rt > 0 else 0.0
    cpu = float(data.get("cpu") or 0.0)

    try:
        dt = float(data.get("diskTotal") or 0.0)
        du = float(data.get("diskUsed") or 0.0)
    except Exception:
        dt = du = 0.0

    _metrics_cache[hostname] = {
        "ts": ts_aware,
        "name": hostname,
        "ip": str(data.get("ip") or data.get("ip_address") or ""),
        "status": "up",
        "cpu": cpu,
        "ramTotal": int(rt),
        "ramUsed": int(ru),
        "diskTotal": int(dt),
        "diskUsed": int(du),
        "netIn": int(data.get("netIn") or 0),
        "netOut": int(data.get("netOut") or 0),
    }

    if cpu >= CPU_HIGH or ram_ratio >= RAM_RATIO_HIGH:
        reasons = []
        if cpu >= CPU_HIGH: reasons.append(f"CPU {cpu:.1f}% >= {CPU_HIGH:.1f}%")
        if ram_ratio >= RAM_RATIO_HIGH: reasons.append(f"RAM ratio {ram_ratio:.2f} >= {RAM_RATIO_HIGH:.2f}")
        description = "Resource usage threshold exceeded: " + ", ".join(reasons)
        _insert_alert(
            hostname=hostname, category="RESOURCE",
            description=description, severity="CRITICAL", label="Critical issue",
            cpu=cpu, ram_ratio=ram_ratio
        )

    return JSONResponse({
        "ok": True, "saved_file": file_path, "resource_alerted": cpu >= CPU_HIGH or ram_ratio >= RAM_RATIO_HIGH
    })

@app.post("/collect-data")
async def collect_data_compat(request: Request):
    return await collect_metrics(request)

@app.post("/collect-hashes")
async def collect_hashes(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
        hostname = (payload.get("hostname") or "").strip()
        hashes = payload.get("hashes") or []
        if not hostname or not isinstance(hashes, list):
            raise ValueError("hostname and hashes are required")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON structure")

    json_path, ts_aware = _save_json_to_disk(payload)
    try:
        with engine.begin() as conn:
            conn.execute(insert(logs).values(
                device_id=None,
                device_name=hostname,
                log_path=json_path,
                severity="HASH",
                created_at=_utcnow_naive(),
            ))
    except SQLAlchemyError as e:
        print("[DB] insert logs failed:", e)

    MAX_ROWS = 20000
    hashes = hashes[:MAX_ROWS]
    ts_now = _utcnow_tz()

    rows = []
    sha_set = set()
    for h in hashes:
        fp = str(h.get("file_path") or "")
        if not fp: continue
        sha = h.get("sha256")
        size = h.get("size")
        mtime = _parse_iso_to_aware(h.get("mtime"))
        err = h.get("error")
        rows.append({
            "ts": ts_now, "hostname": hostname, "file_path": fp[:1024],
            "sha256": (str(sha) if sha else None),
            "size": (int(size) if isinstance(size, (int, float)) else None),
            "mtime": mtime, "error": (str(err)[:512] if err else None)
        })
        if sha and isinstance(sha, str) and len(sha) == 64:
            sha_set.add(sha.lower())

    print(f"Received sha_set: {sha_set}")  # הוספתי לוגינג זמני
    bad_hashes = sha_set.intersection(suspicious_hashes_set)
    print(f"Matched bad_hashes: {bad_hashes}")  # הוספתי לוגינג זמני

    if rows:
        with engine.begin() as conn:
            conn.execute(insert(file_hashes), rows)

    inserted_alerts = 0
    if bad_hashes:
        for h in rows:
            sha = (h["sha256"] or "").lower() if h["sha256"] else None
            if sha in bad_hashes:
                description = f"Malware detected: malicious hash ({sha}) found in file: {h['file_path']}"
                _insert_alert(
                    hostname=hostname, category="HASH",
                    description=description, severity="CRITICAL", label="Malicious Hash",
                    file_path=h["file_path"], sha256=sha
                )
                inserted_alerts += 1

    return JSONResponse({"ok": True, "inserted_hash_rows": len(rows), "alerts_created": inserted_alerts, "json_saved": json_path})

@app.get("/api/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=500)) -> List[dict]:
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                select(
                    alerts.c.id, alerts.c.ts, alerts.c.hostname, alerts.c.category,
                    alerts.c.severity, alerts.c.label, alerts.c.description,
                    alerts.c.file_path, alerts.c.sha256, alerts.c.cpu, alerts.c.ram_ratio
                ).order_by(desc(alerts.c.id)).limit(limit)
            ).mappings().all()
            return [dict(r) for r in rows]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

@app.get("/api/logs")
def get_logs(limit: int = Query(50, ge=1, le=500)) -> List[dict]:
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                select(
                    logs.c.id, logs.c.device_id, logs.c.device_name,
                    logs.c.log_path, logs.c.severity, logs.c.created_at
                ).order_by(desc(logs.c.id)).limit(limit)
            ).mappings().all()
            return [dict(r) for r in rows]
    except SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

@app.get("/api/metrics")
def api_metrics() -> dict:
    now = datetime.now(timezone.utc)
    servers = []
    up_count = down_count = 0
    cpu_vals = []
    ram_pct_vals = []

    for host, m in list(_metrics_cache.items()):
        age = (now - m["ts"]).total_seconds() if isinstance(m["ts"], datetime) else STALE_SECS + 1
        status = "up" if age <= STALE_SECS else "down"
        if status == "up": up_count += 1
        else: down_count += 1

        cpu_vals.append(float(m.get("cpu") or 0.0))
        rt = float(m.get("ramTotal") or 0.0)
        ru = float(m.get("ramUsed") or 0.0)
        ram_pct_vals.append((ru / rt * 100.0) if rt > 0 else 0.0)

        servers.append({
            "name": m.get("name") or host,
            "ip": m.get("ip") or "",
            "status": status,
            "cpu": float(m.get("cpu") or 0.0),
            "ramTotal": int(m.get("ramTotal") or 0),
            "ramUsed": int(m.get("ramUsed") or 0),
            "diskTotal": int(m.get("diskTotal") or 0),
            "diskUsed": int(m.get("diskUsed") or 0),
            "netIn": int(m.get("netIn") or 0),
            "netOut": int(m.get("netOut") or 0),
        })

    avg_cpu = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0.0
    avg_ram = sum(ram_pct_vals) / len(ram_pct_vals) if ram_pct_vals else 0.0
    _history_up.append(up_count)
    _history_down.append(down_count)
    _history_cpu.append(round(avg_cpu, 2))
    _history_ram.append(round(avg_ram, 2))

    return {"servers": servers, "history": {"up": list(_history_up), "down": list(_history_down), "cpu": list(_history_cpu), "ram": list(_history_ram)}}