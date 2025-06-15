import time
import json
import subprocess
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BINDINGS_FILE = "mac_ipv6_bindings_dynamic.json"

class BindingChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(BINDINGS_FILE):
            print(f"[+] Cambio detectado en {BINDINGS_FILE}, aplicando ACLs...")
            apply_acls()

def apply_acls():
    try:
        with open(BINDINGS_FILE, "r") as f:
            bindings = json.load(f)
    except Exception as e:
        print(f"[!] Error al leer el archivo: {e}")
        return

    interfaces_ipv6 = defaultdict(list)

    for entry in bindings:
        iface = entry.get("interface")
        if iface:
            if entry.get("ipv6_link_local"):
                interfaces_ipv6[iface].append(entry["ipv6_link_local"])
            if entry.get("ipv6_global"):
                interfaces_ipv6[iface].append(entry["ipv6_global"])

    commands = ["enter candidate"]

    for iface, ipv6_list in interfaces_ipv6.items():
        entry_id = 10
        for ipv6 in ipv6_list:
            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {entry_id} match ipv6 next-header icmp6 source-ip prefix {ipv6}/128"
            )
            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {entry_id} action accept"
            )
            entry_id += 1

        commands.append(
            f"set acl acl-filter {iface} type ipv6 entry 100 match ipv6 next-header icmp6"
        )
        commands.append(
            f"set acl acl-filter {iface} type ipv6 entry 100 action drop"
        )
        commands.append(
            f"set acl interface {iface} input acl-filter {iface} type ipv6"
        )

    commands.append("commit stay")

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cli",
        "params": {
            "commands": commands
        }
    }

    json_payload = json.dumps(payload)

    curl_command = [
        "curl", "-k", "-u", "admin:NokiaSrl1!",
        "-X", "POST", "http://srlswitch/jsonrpc",
        "-H", "Content-Type: application/json",
        "-d", json_payload
    ]

    print("[*] Enviando comandos al SR Linux...")
    result = subprocess.run(curl_command, capture_output=True, text=True)
    print("Respuesta del servidor:")
    print(result.stdout)

def start_monitor():
    print(f"[*] Iniciando monitor sobre {BINDINGS_FILE}...")
    event_handler = BindingChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, ".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitor()
