from __future__ import annotations
import argparse
import platform
import socket
import uuid
import psutil
import requests
import os
import hashlib
import time
from datetime import datetime, timezone
from typing import List, Optional, Iterable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ---------- helpers ----------
def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def get_mac() -> str:
    mac = uuid.getnode()
    return ":".join(["{:02x}".format((mac >> ele) & 0xff) for ele in range(40, -1, -8)])

# ---------- metrics ----------
def collect_metrics() -> dict:
    """אוסף מדדים מהמערכת המקומית ושלח לשרת"""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    vmem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            procs.append(p.info)
        except Exception:
            pass
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                conns.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status,
                    "pid": c.pid,
                })
            except Exception:
                pass
    except Exception:
        pass

    return {
        "time_local": iso_now(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "mac_address": get_mac(),
        "cpu": float(cpu_percent),
        "ramTotal": int(vmem.total),
        "ramUsed": int(vmem.used),
        "diskTotal": int(disk.total),
        "diskUsed": int(disk.used),
        "processes": procs[:300],
        "connections": conns[:500],
    }

def send_metrics(server_url: str, payload: dict, timeout: int = 20) -> None:
    """שולח את המדדים לשרת"""
    url = server_url.rstrip("/") + "/collect-metrics"  # חשוב: זה הנתיב הנכון
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()

# ---------- hashing ----------
def _iter_files(paths: Iterable[str], follow_symlinks: bool = False) -> Iterable[str]:
    """איטרציה בטוחה על קבצים בתיקיות נתונות"""
    for base in paths:
        base = os.path.expanduser(base)
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base, followlinks=follow_symlinks):
            for name in files:
                yield os.path.join(root, name)

def _hash_file(fp: str, max_size_bytes: Optional[int]) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
    """מחשב SHA-256 לקובץ יחיד, בכפוף למגבלת גודל"""
    try:
        st = os.stat(fp)
        size = int(st.st_size)
        if max_size_bytes is not None and size > max_size_bytes:
            return (fp, None, size, "size_exceeds_limit")
        h = hashlib.sha256()
        with open(fp, "rb", buffering=1024 * 1024) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return (fp, h.hexdigest(), size, None)
    except Exception as e:
        try:
            size = int(os.path.getsize(fp))
        except Exception:
            size = None
        return (fp, None, size, str(e)[:200])

def _ts_to_iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

def collect_file_hashes(
    dirs: List[str], max_size_mb: int, max_files: Optional[int], follow_symlinks: bool, workers: int
) -> List[dict]:
    """סורק את התיקיות, מחשב האשים ומחזיר רשימת רשומות לשליחה לשרת"""
    max_size_bytes = None if max_size_mb is None or max_size_mb < 0 else max_size_mb * 1024 * 1024
    files = []
    for i, fp in enumerate(_iter_files(dirs, follow_symlinks=follow_symlinks), start=1):
        files.append(fp)
        if max_files and i >= max_files:
            break

    results: List[dict] = []
    if not files:
        return results

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(_hash_file, fp, max_size_bytes): fp for fp in files}
        for fut in as_completed(futures):
            fp, sha, size, err = fut.result()
            try:
                mtime = _ts_to_iso_utc(os.path.getmtime(fp))
            except Exception:
                mtime = None
            results.append({
                "file_path": fp,
                "sha256": sha,
                "size": size,
                "mtime": mtime,
                "error": err
            })
    return results

def send_hashes(server_url: str, hostname: str, hashes: List[dict], timeout: int = 60, chunk_size: int = 2000) -> None:
    """שולח את רשימת ההאשים לשרת במנות"""
    url = server_url.rstrip("/") + "/collect-hashes"
    for i in range(0, len(hashes), chunk_size):
        batch = hashes[i:i + chunk_size]
        r = requests.post(url, json={"hostname": hostname, "hashes": batch}, timeout=timeout)
        r.raise_for_status()

# ---------- loops ----------
def metrics_loop(server: str, interval: int):
    """לולאת שליחה מחזורית של מדדים"""
    while True:
        try:
            payload = collect_metrics()
            send_metrics(server, payload)
        except Exception as e:
            print("[METRICS ERROR]", e)
        time.sleep(max(1, int(interval)))

def hash_loop(server: str, dirs: List[str], interval: int, max_size_mb: int, max_files: int, workers: int):
    """לולאת סריקה מחזורית של קבצים ושליחת האשים"""
    hostname = socket.gethostname()
    while True:
        try:
            print(f"[HASH] scanning {len(dirs)} dir(s): {dirs}")
            hashes = collect_file_hashes(
                dirs=dirs,
                max_size_mb=max_size_mb,
                max_files=max_files,
                follow_symlinks=False,
                workers=workers
            )
            print(f"[HASH] collected {len(hashes)} entries; sending...")
            if hashes:
                send_hashes(server, hostname, hashes)
                print("[HASH OK] sent batch")
            else:
                print("[HASH OK] []")
        except Exception as e:
            print("[HASH ERROR]", e)
        time.sleep(max(60, int(interval)))

# ---------- main ----------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--metrics-interval", type=int, default=5)
    p.add_argument("--hash", dest="hash_enable", action="store_true")
    p.add_argument("--hash-dirs", nargs="*", help="Dirs to scan; default: /host if mounted")
    p.add_argument("--hash-interval", type=int, default=3600)
    p.add_argument("--max-size-mb", type=int, default=100)
    p.add_argument("--max-files", type=int, default=5000)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()

    # הערה: אם לא הועברו hash-dirs כארגומנט, ננסה מה-ENV או ניפול להום
    if args.hash_dirs:
        dirs = args.hash_dirs
    else:
        env_dirs = os.environ.get("HASH_DIRS")
        if env_dirs:
            # מאפשר רווחים מופרדים
            dirs = env_dirs.split()
        elif os.path.isdir("/host"):
            dirs = ["/host"]
        else:
            dirs = [os.path.expanduser("~")]

    print(f"[agent] server: {args.server}")
    print(f"[agent] metrics interval: {args.metrics_interval}s")
    print(f"[agent] hashing {'enabled' if args.hash_enable else 'disabled'}; dirs: {dirs}")

    t1 = threading.Thread(target=metrics_loop, args=(args.server, args.metrics_interval), daemon=True)
    t1.start()

    if args.hash_enable:
        # תיקון: שימוש ב-args.max_size_mb (לא mB)
        t2 = threading.Thread(
            target=hash_loop,
            args=(args.server, dirs, args.hash_interval, args.max_size_mb, args.max_files, args.workers),
            daemon=True
        )
        t2.start()

    # שמירה על התהליך חי
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
