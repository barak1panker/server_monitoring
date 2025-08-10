
import hashlib
import os
from typing import Iterable, Dict, List, Tuple
import psycopg2
import psycopg2.extras as extras

def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("PGDATABASE", "monitor-info"),
        user=os.getenv("PGUSER", "postgres"),
        password=os.getenv("PGPASSWORD", ""),
        host=os.getenv("PGHOST", "localhost"),
        port=os.getenv("PGPORT", "5432"),
    )

def init_schema(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
              id BIGSERIAL PRIMARY KEY,
              device_id BIGINT,
              path TEXT NOT NULL,
              algo TEXT NOT NULL DEFAULT 'sha256',
              hash TEXT NOT NULL,
              scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              UNIQUE (algo, hash, path)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS suspicious_hashes (
              algo TEXT NOT NULL DEFAULT 'sha256',
              hash TEXT PRIMARY KEY,
              threat_name TEXT,
              severity TEXT,
              source TEXT,
              first_seen TIMESTAMPTZ DEFAULT now(),
              last_seen  TIMESTAMPTZ DEFAULT now()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_files_hash ON files (algo, hash)
        """)
    conn.commit()

def file_hash(path: str, algo: str = "sha256", chunk: int = 1 << 20) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest().lower()

def check_hash(conn, digest: str, algo: str = "sha256") -> Dict:
    digest = digest.lower()
    with conn.cursor(cursor_factory=extras.DictCursor) as cur:
        cur.execute("""
            SELECT threat_name, severity
            FROM suspicious_hashes
            WHERE algo=%s AND hash=%s
        """, (algo, digest))
        sus = cur.fetchone()
        cur.execute("""
            SELECT 1
            FROM files
            WHERE algo=%s AND hash=%s
            LIMIT 1
        """, (algo, digest))
        known = cur.fetchone() is not None
    return {
        "hash": digest,
        "algo": algo,
        "is_known": known,
        "is_suspicious": sus is not None,
        "threat_name": sus["threat_name"] if sus else None,
        "severity": sus["severity"] if sus else None,
    }

def check_hashes(conn, digests: Iterable[str], algo: str = "sha256") -> Dict[str, Dict]:
    q_list = sorted({d.lower() for d in digests})
    if not q_list:
        return {}
    with conn.cursor(cursor_factory=extras.DictCursor) as cur:
        cur.execute("""
            SELECT hash, threat_name, severity
            FROM suspicious_hashes
            WHERE algo=%s AND hash = ANY(%s)
        """, (algo, q_list))
        suspicious_map = {row["hash"]: (row["threat_name"], row["severity"]) for row in cur}
        cur.execute("""
            SELECT DISTINCT hash
            FROM files
            WHERE algo=%s AND hash = ANY(%s)
        """, (algo, q_list))
        known_set = {row["hash"] for row in cur}
    out: Dict[str, Dict] = {}
    for h in q_list:
        t_s = suspicious_map.get(h)
        out[h] = {
            "hash": h,
            "algo": algo,
            "is_known": h in known_set,
            "is_suspicious": t_s is not None,
            "threat_name": t_s[0] if t_s else None,
            "severity": t_s[1] if t_s else None,
        }
    return out

def record_files(conn, device_id: int, items: List[Tuple[str, str]], algo: str = "sha256"):
    rows = []
    for path, h in items:
        rows.append((device_id, path, algo, h.lower()))
    with conn.cursor() as cur:
        extras.execute_values(cur, """
            INSERT INTO files (device_id, path, algo, hash)
            VALUES %s
            ON CONFLICT (algo, hash, path) DO NOTHING
        """, rows)
    conn.commit()

if __name__ == "__main__":
    conn = get_conn()
    try:
        init_schema(conn)
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        info = check_hash(conn, digest)
        print("single:", info)
        batch = [digest, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        infos = check_hashes(conn, batch)
        print("batch:", infos)
        record_files(conn, device_id=1, items=[("/tmp/empty.txt", digest)])
    finally:
        conn.close()
