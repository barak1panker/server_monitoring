from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
import os
import json
import psycopg2

app = FastAPI(
    title="Server Monitoring API",
    description="API for monitoring server status and performance",
    version="1.0.0"
)

UPLOAD_DIR = r"C:\Logs"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# PostgreSQL connection details
DB_CONFIG = {
    "dbname": "monitor-info",
    "user": "postgres",
    "password": "19979797h",
    "host": "localhost",
    "port": "5433"
}

@app.post("/collect-data", summary="Collect server data")
async def collect_data(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON format.")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object.")

    required_keys = ["hostname", "platform", "processes", "connections", "usb_devices", "mac_address", "json_path", "file_hashes"]
    missing = [key for key in required_keys if key not in data]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing keys: {missing}")

    # Optional: save a backup copy of the JSON data to local logs
    try:
        local_filename = f"{data['hostname']}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
        local_path = os.path.join(UPLOAD_DIR, local_filename)
        with open(local_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print("Warning: Failed to save local backup JSON:", e)

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 1️⃣ הכנס או עדכן את המכשיר בטבלת devices
        cur.execute("""
            INSERT INTO devices (device_name, description, mac_address, json_path)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
        """, (data["hostname"], "Collected from agent", data["mac_address"], data["json_path"]))
        device_id = cur.fetchone()[0]

        # 2️⃣ הכנס את כל ה‑file_hashes בטבלת file_hashes
        file_hashes = data["file_hashes"]  # ציפייה לרשימה של dict עם {"path": ..., "hash": ...}
        for f in file_hashes:
            cur.execute("""
                INSERT INTO file_hashes (device_id, file_path, file_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING;
            """, (device_id, f["path"], f["hash"]))

        # 3️⃣ השוואת hash מול malicious_hashes ויצירת alerts
        cur.execute("""
            INSERT INTO alerts (device_id, file_hash)
            SELECT f.device_id, f.file_hash
            FROM file_hashes f
            JOIN malicious_hashes m ON LOWER(f.file_hash) = m.file_hash
            WHERE f.device_id = %s
            ON CONFLICT DO NOTHING;
        """, (device_id,))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("❌ Database error:", e)
        raise HTTPException(status_code=500, detail="Database error")

    return JSONResponse(content={
        "message": "Data collected and saved successfully",
        "device_id": device_id,
        "timestamp": datetime.now().isoformat()
    })
