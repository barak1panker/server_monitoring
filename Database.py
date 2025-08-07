import psycopg2

# PostgreSQL connection configuration
DB_CONFIG = {
    "dbname": "monitor-info",
    "user": "postgres",
    "password": "19979797h",
    "host": "localhost",
    "port": "5433"
}

# Connect to the database
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

# Create the devices table if it does not exist
cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        device_name TEXT,
        description TEXT,
        mac_address TEXT,
        json_path TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

# Example static data to insert
device_name = "Device-A"
description = "Main Server"
mac_address = "00:11:22:33:44:55"
json_path = "logs/Device-A_2025-08-01_15-00-00.json"

# Insert the test data into the devices table
cur.execute("""
    INSERT INTO devices (device_name, description, mac_address, json_path)
    VALUES (%s, %s, %s, %s)
    RETURNING id;
""", (device_name, description, mac_address, json_path))

# Get the inserted ID
device_id = cur.fetchone()[0]
print("Inserted Device ID:", device_id)

# Finalize transaction and close the connection
conn.commit()
cur.close()
conn.close()
