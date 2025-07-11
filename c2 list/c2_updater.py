import os
import sys
import requests
import zipfile
import io
import json
import socket

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

def has_internet(host="8.8.8.8", port=53, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except Exception:
        return False

def get_output_path():
    if getattr(sys, 'frozen', False):
        # Running from compiled .exe
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running from script
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "known_c2.txt")

def update_c2_list(output_path=None):
    output_path = output_path or get_output_path()

    if not has_internet():
        print("🚫 No internet connection. Unable to update C2 list.")
        return

    print("🔄 Downloading ThreatFox ZIP archive...")
    url = "https://threatfox.abuse.ch/export/json/full/"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        zip_content = zipfile.ZipFile(io.BytesIO(response.content))
        json_file = next((f for f in zip_content.namelist() if f.endswith(".json")), None)

        if not json_file:
            print("❌ No JSON file found in ZIP.")
            return

        data = json.loads(zip_content.read(json_file))
        c2_ips = set()

        for entries in data.values():
            for item in entries:
                if item["ioc_type"] in ("ip", "ip:port"):
                    ip = item["ioc_value"].split(":")[0]
                    c2_ips.add(ip)

        with open(output_path, "w") as f:
            for ip in sorted(c2_ips):
                f.write(f"{ip}\n")

        print(f"✅ C2 list updated with {len(c2_ips)} IPs.")
        print(f"[Saved at: {output_path}]")

    except Exception as e:
        print(f"❌ Failed to update C2 list: {e}")

if __name__ == "__main__":
    update_c2_list()
