import socket
import subprocess
import time

def is_port_open(host="127.0.0.1", port=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def ensure_container_running():
    if is_port_open():
        return

    subprocess.Popen([
        "docker", "run",
        "-p", "8080:8080",
        "-m", "1g",
        "zacharydaniel229/malware-defense:latest"
    ])
    for _ in range(20):  # ~20 seconds max
        if is_port_open():
            print("Container is now running.")
            return
        time.sleep(1)

    print("Warning: container did not start within expected time.")

ensure_container_running()
