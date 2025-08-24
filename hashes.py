import psycopg2

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
# File path
# ----------------------------
INPUT_FILE = r"C:\hashes\full_sha256.txt"

# ----------------------------
# Table names
# ----------------------------
TABLE_NAME = "hashes_table"
MALICIOUS_TABLE = "malicious_hashes"

# ----------------------------
# Connect to PostgreSQL
# ----------------------------
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

# ----------------------------
# Create tables if not exists
# ----------------------------
cur.execute(f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id SERIAL PRIMARY KEY,
    hash_value TEXT UNIQUE
);
""")
cur.execute(f"""
CREATE TABLE IF NOT EXISTS {MALICIOUS_TABLE} (
    id SERIAL PRIMARY KEY,
    file_hash VARCHAR(64) UNIQUE,
    description TEXT,
    source TEXT
);
""")
conn.commit()

# ----------------------------
# Clear old data in hashes_table (so no duplicates remain)
# ----------------------------
cur.execute(f"TRUNCATE TABLE {TABLE_NAME};")
conn.commit()

# ----------------------------
# Read TXT and insert into both tables
# ----------------------------
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    lines = [line.strip() for line in f if line.strip()]

# Insert into hashes_table (as-is)
for hash_line in lines:
    cur.execute(
        f"INSERT INTO {TABLE_NAME} (hash_value) VALUES (%s) ON CONFLICT DO NOTHING;",
        (hash_line,)
    )

# Insert into malicious_hashes (lowercase)
for hash_line in lines:
    cur.execute(
        f"""
        INSERT INTO {MALICIOUS_TABLE} (file_hash, description, source)
        VALUES (%s, %s, %s)
        ON CONFLICT DO NOTHING;
        """,
        (hash_line.lower(), "Imported from full_sha256.txt", "TXT file")
    )

conn.commit()
print(f"Inserted {len(lines)} hashes into {TABLE_NAME} and {MALICIOUS_TABLE}.")

# ----------------------------
# Close connection
# ----------------------------
cur.close()
conn.close()
