import psutil
import socket
import platform
import requests
import json
import os
import hashlib
import datetime
import uuid

# Returns the MAC address of the machine in readable format
def get_mac():
    mac = uuid.getnode()
    return ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(40, -1, -8)])

# Collects system data including hostname, MAC, platform, processes, connections, USB devices, and file hashes
def collect_data():
    data = {
        "hostname": socket.gethostname(),
        "mac_address": get_mac(),
        "platform": platform.platform(),
        "processes": [p.info for p in psutil.process_iter(['pid', 'name'])],
        "connections": [conn._asdict() for conn in psutil.net_connections()],
        "usb_devices": get_usb_devices(),
        "file_hashes": get_file_hashes()
    }
    return data

# Saves collected data to a local JSON file and returns the file path
def save_json(data):
    upload_dir =  r"C:\Logs"  # Use your existing folder
    os.makedirs(upload_dir, exist_ok=True)  # Ensure the folder exists
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(upload_dir, f"{data['hostname']}_{timestamp}.json")
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    return filename

# Sends collected data to the backend API endpoint
def send_data(data):
    url = "http://127.0.0.1:8000/collect-data"
    try:
        response = requests.post(url, data=json.dumps(data), headers={"Content-Type": "application/json"})
        print(f"Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print("Failed to send data:", e)

# Returns a list of USB device IDs connected to the machine
def get_usb_devices():
    try:
        import wmi
        c = wmi.WMI()
        devices = [usb.DeviceID for usb in c.Win32_USBHub()]
        return devices
    except:
        return []

# Calculates the hash value of a given file using the specified algorithm (default is SHA-256)
def calculate_hash(file_path, algorithm='sha256'):
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None

# Walks through a directory and returns a list of hashes for all files with the given extension
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

# Entry point of the script: collect data, save it to JSON, and send it to the server
if __name__ == "__main__":
    data = collect_data()
    json_path = save_json(data)
    data["json_path"] = json_path  # Add the path to the JSON file in the data being sent
    print("Data collected and saved to:", json_path)
    send_data(data)
