import json
import subprocess

# Ruta al archivo con las bindings
bindings_file = "/data/mac_ipv6_bindings_dynamic.json"

# Leer los datos del archivo JSON
with open(bindings_file, "r") as f:
    bindings = json.load(f)

# Crear comandos CLI a partir de las direcciones IPv6
commands = ["enter candidate"]

for entry in bindings:
    if "ipv6_link_local" in entry and entry["ipv6_link_local"]:
        commands.append(f"set acl match-list ipv6-prefix-list permitidos prefix {entry['ipv6_link_local']}/128")
    if "ipv6_global" in entry and entry["ipv6_global"]:
        commands.append(f"set acl match-list ipv6-prefix-list permitidos prefix {entry['ipv6_global']}/128")

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
