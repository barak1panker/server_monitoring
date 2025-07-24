import psutil
import socket
import platform
import requests
import json
import winreg

def collect_data():
    data = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "processes": [p.info for p in psutil.process_iter(['pid', 'name'])],
        "connections": [conn._asdict() for conn in psutil.net_connections()],
        "usb_devices": get_usb_devices(),
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


if __name__ == "__main__":
    data = collect_data()
    print(data)
    send_data(data)     