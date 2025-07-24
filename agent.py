import psutil
import socket
import platform
import requests
import json
import winreg
import os
import hashlib

def collect_data():
    data = {
        "hostname": socket.gethostname(),
        "mac_address": get_mac(),
        "platform": platform.platform(),
        "processes": [p.info for p in psutil.process_iter(['pid', 'name'])],
        "connections": [conn._asdict() for conn in psutil.net_connections()],
        "usb_devices": get_usb_devices(),
        "file_hashes": get_file_hashes()  # ⬅️ תוספת חדשה
    }
    return data

def get_usb_devices():
    try:
        import wmi
        c = wmi.WMI()
        devices = []
        for usb in c.Win32_USBHub():
            devices.append(usb.DeviceID)
        return devices
    except:
        return []

def send_data(data):
    url = "http://127.0.0.1:8000/collect-data"    
    requests.post(url, data=json.dumps(data))

def calculate_hash(file_path, algorithm='sha256'):
    
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None

def get_file_hashes(directory=r"C:\Program Files", extension=".exe"):
 
    hashes = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(extension):
                full_path = os.path.join(root, file)
                hash_val = calculate_hash(full_path)
                if hash_val:
                    hashes.append({
                        "path": full_path,
                        "hash": hash_val
                    })
    return hashes


if __name__ == "__main__":
    data = collect_data()
    print(data)
    send_data(data)     