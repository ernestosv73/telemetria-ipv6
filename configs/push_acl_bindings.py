import json
import subprocess

# Ruta al archivo con las bindings
bindings_file = "/data/mac_ipv6_bindings_dynamic.json"

# Leer los datos del archivo JSON
with open(bindings_file, "r") as f:
    bindings = json.load(f)

# Crear comandos CLI a partir de las direcciones IPv6
commands = ["enter candidate"]

# Llevar registro de interfaces únicas para aplicar acl
interfaces_configuradas = set()

for entry in bindings:
    # Agregar direcciones a la prefix-list
    if "ipv6_link_local" in entry and entry["ipv6_link_local"]:
        commands.append(f"set acl match-list ipv6-prefix-list permitidos prefix {entry['ipv6_link_local']}/128")
    if "ipv6_global" in entry and entry["ipv6_global"]:
        commands.append(f"set acl match-list ipv6-prefix-list permitidos prefix {entry['ipv6_global']}/128")

    # Aplicar ACL a la interfaz si aún no fue configurada
    iface = entry.get("interface")
    if iface and iface not in interfaces_configuradas:
        commands.append(f"set acl interface {iface} input acl-filter icmpv6 type ipv6")
        interfaces_configuradas.add(iface)

commands.append("commit stay")

# Armar el payload JSON-RPC
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "cli",
    "params": {
        "commands": commands
    }
}

# Convertir el payload a string JSON
json_payload = json.dumps(payload)

# Ejecutar curl
curl_command = [
    "curl", "-k", "-u", "admin:NokiaSrl1!",
    "-X", "POST", "http://srlswitch/jsonrpc",
    "-H", "Content-Type: application/json",
    "-d", json_payload
]

# Ejecutar y mostrar resultado
result = subprocess.run(curl_command, capture_output=True, text=True)
print("Respuesta del servidor:")
print(result.stdout)
