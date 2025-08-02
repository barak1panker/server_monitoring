import psycopg2

conn = psycopg2.connect(
    dbname='monitor-info',
    user='postgres',
    password='19979797h',
    host='localhost',
    port='5433'
)

cur = conn.cursor()


cur.execute("""
    ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS mac_address TEXT,
    ADD COLUMN IF NOT EXISTS json_path TEXT;
""")


device_name = "Device-A"
description = "main server"
mac_address = "00:11:22:33:44:55"
json_path = "logs/Device-A_2025-08-01_15-00-00.json"

cur.execute("""
    INSERT INTO devices (device_name, description, mac_address, json_path)
    VALUES (%s, %s, %s, %s)
    RETURNING id;
""", (device_name, description, mac_address, json_path))

device_id = cur.fetchone()[0]
print("ID :", device_id)

conn.commit()
cur.close()
conn.close()
