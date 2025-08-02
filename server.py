from fastapi import FastAPI,  File, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
import os
from typing import List
from fastapi import Request
import json
import psycopg2



app = FastAPI(
    title="Server Monitoring API",
    description="API for monitoring server status and performance",
    version="1.0.0"
)

IP = "172.0.0.1"
port = 8000
UPLOAD_DIR = "logs"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post(
    "/collect-data",
    summary="Collect server data",
    description="Collects data about the server's processes, connections, and USB devices."
)
async def collect_data(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON format.")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object.")

    required_keys = ["hostname", "platform", "processes", "connections", "usb_devices", "mac_address"]
    missing = [key for key in required_keys if key not in data]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing keys: {missing}")

    filename = f"{data['hostname']}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
    filepath = os.path.join(UPLOAD_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        print(data)
        json.dump(data, f, indent=4)

    print(f"Data collected from {data['hostname']} at {datetime.now()}")

    # ✅ שלב חדש: שמירה למסד הנתונים
    try:
        import psycopg2
        conn = psycopg2.connect(
            dbname='monitor-info',
            user='postgres',
            password='',  # אם יש סיסמה - הכנס כאן
            host='localhost',
            port='5433'
        )
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO devices (device_name, mac_address, json_path)
            VALUES (%s, %s, %s);
        """, (
            data["hostname"],
            data["mac_address"],
            filepath
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")

    return JSONResponse(content={
        "message": "Data collected successfully",
        "timestamp": datetime.now().isoformat()
    })