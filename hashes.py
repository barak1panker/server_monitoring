import psycopg2
import os

# ----------------------------
# PostgreSQL connection config
# ----------------------------
DB_CONFIG = {
    "dbname": "monitor-info",
    "user": "postgres",
    "password": "19979797h",
    "host": "localhost",
    "port": "5433"
}

# ----------------------------
# File paths
# ----------------------------
INPUT_FILE = r"C:\hashes\full_sha256.txt"       # Original TXT file
BACKUP_FILE = r"C:\hashes\hashes_backup.txt"    # Automatic backup TXT

# ----------------------------
# Table name
# ----------------------------
TABLE_NAME = "hashes_table"

# ----------------------------
# Connect to PostgreSQL
# ----------------------------
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

# ----------------------------
# Create table if not exists
# ----------------------------
cur.execute(f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id SERIAL PRIMARY KEY,
    hash_value TEXT
);
""")
conn.commit()

# ----------------------------
# Read TXT and insert into table
# ----------------------------
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    lines = [line.strip() for line in f if line.strip()]

inserted_count = 0
for hash_line in lines:
    try:
        # simple insert without ON CONFLICT
        cur.execute(
            f"INSERT INTO {TABLE_NAME} (hash_value) VALUES (%s);",
            (hash_line,)
        )
        conn.commit()  # commit each row to avoid transaction abort
        inserted_count += 1
    except Exception as e:
        print(f"Failed to insert {hash_line}: {e}")
        conn.rollback()  # reset transaction on error

print(f"Inserted {inserted_count} hashes into {TABLE_NAME}.")

# ----------------------------
# Automatic backup to TXT
# ----------------------------
try:
    cur.execute(f"SELECT hash_value FROM {TABLE_NAME};")
    rows = cur.fetchall()

    os.makedirs(os.path.dirname(BACKUP_FILE), exist_ok=True)
    with open(BACKUP_FILE, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(row[0] + "\n")

    print(f"Backup saved automatically as {BACKUP_FILE}")
except Exception as e:
    print(f"Failed to create backup: {e}")

# ----------------------------
# Close connection
# ----------------------------
cur.close()
conn.close()
