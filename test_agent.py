from __future__ import annotations
# test_agent.py — standalone local tester (Windows-friendly)
# Notes in Hebrew only; all identifiers/strings are English

import argparse
import os
import sys
import time
import platform
import socket
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Iterable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import requests
import shutil

# Try to import psutil for real metrics; fall back gracefully if missing
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    _HAS_PSUTIL = False
    print("[WARN] psutil is not installed. Metrics will be partial. You can install it with:")
    print("       pip install psutil")

def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def get_mac() -> str:
    mac = uuid.getnode()
    return ":".join(["{:02x}".format((mac >> ele) & 0xff) for ele in range(40, -1, -8)])

# -------- Metrics collection --------
def collect_metrics() -> dict:
    """Collects basic system metrics. Requires psutil for full data."""
    if _HAS_PSUTIL:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        vmem = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("/")
            disk_total = int(disk.total)
            disk_used = int(disk.used)
        except Exception:
            # Fallback to shutil
            t, u, _ = shutil.disk_usage(os.path.abspath(os.sep))
            disk_total, disk_used = int(t), int(u)
        processes = []
        for p in psutil.process_iter(attrs=["pid", "name"]):
            try:
                processes.append(p.info)
            except Exception:
                pass
        connections = []
        try:
            for c in psutil.net_connections(kind="inet"):
                try:
                    connections.append({
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        "status": c.status,
                        "pid": c.pid,
                    })
                except Exception:
                    pass
        except Exception:
            pass
        ram_total = int(vmem.total)
        ram_used = int(vmem.used)
    else:
        # Minimal placeholders without psutil
        cpu_percent = 0.0
        try:
            t, u, _ = shutil.disk_usage(os.path.abspath(os.sep))
            disk_total, disk_used = int(t), int(u)
        except Exception:
            disk_total = disk_used = 0
        ram_total = ram_used = 0
        processes, connections = [], []

    return {
        "time_local": iso_now(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "mac_address": get_mac(),
        "cpu": float(cpu_percent),
        "ramTotal": ram_total,
        "ramUsed": ram_used,
        "diskTotal": disk_total,
        "diskUsed": disk_used,
        "processes": processes[:300],
        "connections": connections[:500],
    }

def _post_json(url: str, payload: dict, timeout: int) -> None:
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()

def send_metrics(server_url: str, payload: dict, timeout: int = 15) -> None:
    """Try /collect-metrics first; if 404 fallback to /collect-data."""
    base = server_url.rstrip("/")
    try:
        _post_json(base + "/collect-metrics", payload, timeout)
        return
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            _post_json(base + "/collect-data", payload, timeout)
            return
        raise

# -------- Hashing --------
def _iter_files(paths: Iterable[str], follow_symlinks: bool = False) -> Iterable[str]:
    for base in paths:
        base = os.path.expanduser(base)
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base, followlinks=follow_symlinks):
            for name in files:
                yield os.path.join(root, name)

def _hash_file(fp: str, max_size_bytes: Optional[int]) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
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

def send_hashes(server_url: str, hostname: str, hashes: List[dict], timeout: int = 60, chunk_size: int = 1500) -> None:
    url = server_url.rstrip("/") + "/collect-hashes"
    for i in range(0, len(hashes), chunk_size):
        batch = hashes[i:i+chunk_size]
        r = requests.post(url, json={"hostname": hostname, "hashes": batch}, timeout=timeout)
        r.raise_for_status()

# -------- Runner --------
def main():
    parser = argparse.ArgumentParser(description="Local test agent (sends metrics/hashes from this machine).")
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "http://localhost:8000"))
    parser.add_argument("--metrics-interval", type=int, default=int(os.getenv("METRICS_INTERVAL", "5")))
    parser.add_argument("--hash", dest="hash_enable", action="store_true", default=os.getenv("HASH_ENABLE", "true").lower()=="true")
    parser.add_argument("--hash-dirs", nargs="*", default=None, help="Dirs to scan; default: user's home")
    parser.add_argument("--hash-interval", type=int, default=int(os.getenv("HASH_INTERVAL", "1800")))
    parser.add_argument("--max-size-mb", type=int, default=int(os.getenv("AGENT_MAX_SIZE_MB", "50")))
    parser.add_argument("--max-files", type=int, default=int(os.getenv("AGENT_MAX_FILES", "500")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("AGENT_WORKERS", "2")))
    parser.add_argument("--once", action="store_true", help="Send one metrics sample and (optional) one hash scan, then exit.")
    args = parser.parse_args()

    # Default scan dir = user's home (Windows-friendly). Allow env HASH_DIRS to override.
    if args.hash_dirs is None:
        env_dirs = os.getenv("HASH_DIRS")
        if env_dirs:
            args.hash_dirs = env_dirs.split()
        else:
            args.hash_dirs = [os.path.expanduser("~")]

    hostname = socket.gethostname()

    print(f"[test-agent] server: {args.server}")
    print(f"[test-agent] metrics interval: {args.metrics_interval}s")
    print(f"[test-agent] hashing: {args.hash_enable}; dirs: {args.hash_dirs} (every {args.hash_interval}s)")
    if not _HAS_PSUTIL:
        print("[test-agent] psutil not available; sending partial metrics only.")

    last_hash_ts = 0.0
    while True:
        # send metrics
        try:
            payload = collect_metrics()
            print(f"[test-agent] sending metrics cpu={payload.get('cpu')} ram={payload.get('ramUsed')}/{payload.get('ramTotal')} ...")
            send_metrics(args.server, payload)
            print("[test-agent] METRICS OK")
        except Exception as e:
            print("[test-agent] METRICS ERROR:", e)

        # maybe send hashes
        now = time.time()
        if args.hash_enable and (args.once or (now - last_hash_ts >= args.hash_interval)):
            try:
                print(f"[test-agent] hashing {len(args.hash_dirs)} dir(s): {args.hash_dirs}")
                hashes = collect_file_hashes(
                    dirs=args.hash_dirs,
                    max_size_mb=args.max_size_mB if hasattr(args, "max_size_mB") else args.max_size_mb,  # tolerate typo if present
                    max_files=args.max_files,
                    follow_symlinks=False,
                    workers=args.workers
                )
                print(f"[test-agent] collected {len(hashes)} entries; sending...")
                if hashes:
                    send_hashes(args.server, hostname, hashes)
                    print("[test-agent] HASH OK")
                else:
                    print("[test-agent] HASH OK (empty)")
            except Exception as e:
                print("[test-agent] HASH ERROR:", e)
            last_hash_ts = now

        if args.once:
            break
        time.sleep(max(1, int(args.metrics_interval)))

if __name__ == "__main__":
    main()
