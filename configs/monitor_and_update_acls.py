import json
import subprocess
from collections import defaultdict
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# Ruta del archivo a monitorear
bindings_file = "/data/mac_ipv6_bindings_dynamic.json"

# Función para generar los comandos ACL
def generate_acl_commands():
    try:
        with open(bindings_file, "r") as f:
            bindings = json.load(f)
    except Exception as e:
        print(f"Error leyendo el archivo JSON: {e}")
        return []

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
            # Comando con next-header + source-ip en una sola línea
            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {entry_id} match ipv6 next-header icmp6 source-ip prefix {ipv6}/128"
            )
            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {entry_id} action accept"
            )
            entry_id += 1

        # Entrada catch-all: bloquea todo el ICMPv6 no autorizado
        commands.append(
            f"set acl acl-filter {iface} type ipv6 entry 100 match ipv6 next-header icmp6"
        )
        commands.append(
            f"set acl acl-filter {iface} type ipv6 entry 100 action drop"
        )

        # Aplicar ACL a la interfaz
        commands.append(
            f"set acl interface {iface} input acl-filter {iface} type ipv6"
        )

    commands.append("commit stay")

    return commands


# Función para enviar los comandos via curl
def send_to_srlinux(commands):
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

    result = subprocess.run(curl_command, capture_output=True, text=True)
    print("Respuesta del servidor:")
    print(result.stdout)


# Clase para manejar eventos del sistema de archivos
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self.last_modified = 0

    def on_modified(self, event):
        if event.src_path == self.file_path:
            current_time = time.time()
            # Evita disparos múltiples muy seguidos
            if current_time - self.last_modified > 1:
                print(f"[INFO] Cambios detectados en {self.file_path}. Actualizando ACLs...")
                commands = generate_acl_commands()
                if commands:
                    send_to_srlinux(commands)
                self.last_modified = current_time


if __name__ == "__main__":
    print("[INFO] Iniciando monitor de cambios...")

    dir_to_watch = "/data/"  # Directorio donde está el archivo
    file_to_watch = "/data/mac_ipv6_bindings_dynamic.json"

    event_handler = FileChangeHandler(file_to_watch)
    observer = Observer()
    observer.schedule(event_handler, path=dir_to_watch, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
