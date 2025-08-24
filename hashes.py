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
    hash_value TEXT UNIQUE
);
""")
conn.commit()

# ----------------------------
# Clear old data (so no duplicates remain)
# ----------------------------
cur.execute(f"TRUNCATE TABLE {TABLE_NAME};")
conn.commit()

# ----------------------------
# Read TXT and insert into table
# ----------------------------
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    lines = [line.strip() for line in f if line.strip()]

for hash_line in lines:
    cur.execute(
        f"INSERT INTO {TABLE_NAME} (hash_value) VALUES (%s) ON CONFLICT DO NOTHING;",
        (hash_line,)
    )

conn.commit()
print(f"Inserted {len(lines)} hashes into {TABLE_NAME} (same as in TXT file).")

# ----------------------------
# Close connection
# ----------------------------
cur.close()
conn.close()
