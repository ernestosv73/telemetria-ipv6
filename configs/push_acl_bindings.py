import json
import subprocess
from collections import defaultdict

bindings_file = "/data/mac_ipv6_bindings_dynamic.json"

with open(bindings_file, "r") as f:
    bindings = json.load(f)

interfaces_ipv6 = defaultdict(list)

# Agrupa por interfaz
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

# JSON-RPC payload
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "cli",
    "params": {
        "commands": commands
    }
}

json_payload = json.dumps(payload)

# Ejecutar el curl hacia el SR Linux
curl_command = [
    "curl", "-k", "-u", "admin:NokiaSrl1!",
    "-X", "POST", "http://srlswitch/jsonrpc",
    "-H", "Content-Type: application/json",
    "-d", json_payload
]

result = subprocess.run(curl_command, capture_output=True, text=True)
print("Respuesta del servidor:")
print(result.stdout)
