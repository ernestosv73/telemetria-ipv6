#!/usr/bin/env python3

import json
import time
import hashlib
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Configuraciones
JSON_FILE = "/data/mac_ipv6_bindings_dynamic.json"
ES_URL = "http://172.80.80.9:9200"
SRL_URL = "http://srlswitch/jsonrpc"
SRL_USER = "admin"
SRL_PASS = "NokiaSrl1!"
INTERVALO_SEGUNDOS = 30

# Estado
hashes_enviados = {}
ultimo_acl_sentido = None  # Para evitar reenviar ACLs si no hay cambios

# Funciones auxiliares
def is_complete_entry(entry):
    return all([
        entry.get("mac"),
        entry.get("interface"),
        entry.get("ipv6_link_local"),
        entry.get("ipv6_global")
    ])

def hash_entrada(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

def leer_nuevos_bindings():
    nuevos = []
    try:
        if Path(JSON_FILE).exists():
            with open(JSON_FILE, "r") as f:
                data = json.load(f)
                for entry in data:
                    if is_complete_entry(entry):
                        h = hash_entrada(entry)
                        if h not in hashes_enviados:
                            nuevos.append(entry)
                            hashes_enviados[h] = True
        else:
            print(f"[!] Archivo {JSON_FILE} no existe.")
    except Exception as e:
        print(f"[!] Error leyendo JSON: {e}")
    return nuevos

# Elasticsearch
def enviar_bulk_elasticsearch(entries):
    if not entries:
        return
    fecha = datetime.utcnow().strftime("%Y.%m.%d")
    index_name = f"mac-ipv6-{fecha}"
    bulk_url = f"{ES_URL}/{index_name}/_bulk"

    bulk_data = ""
    for entry in entries:
        # Creamos el mensaje legible
        mensaje = f"[{entry.get('timestamp')}] MAC: {entry.get('mac')} | Interface: {entry.get('interface')} | LL: {entry.get('ipv6_link_local')} | GUA: {entry.get('ipv6_global')}"
        # Añadimos el campo 'message'
        entry["message"] = mensaje

        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(entry) + "\n"

    headers = {"Content-Type": "application/json"}
    response = requests.post(bulk_url, headers=headers, data=bulk_data)

    if response.status_code == 200:
        print(f"[+] {len(entries)} entradas enviadas a {index_name}")
    else:
        print(f"[!] Error al enviar a Elasticsearch: {response.status_code}")
        print(response.text)


# ACLs para SR Linux
def bindings_acl_hash(bindings):
    return hashlib.sha256(json.dumps(bindings, sort_keys=True).encode()).hexdigest()

def build_and_send_acls(bindings):
    global ultimo_acl_sentido

    acl_hash = bindings_acl_hash(bindings)
    if acl_hash == ultimo_acl_sentido:
        print("[=] ACLs ya enviadas. Sin cambios.")
        return

    interfaces_ipv6 = defaultdict(list)
    for entry in bindings:
        iface = entry["interface"]
        interfaces_ipv6[iface].append(entry["ipv6_link_local"])
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

        commands.append(f"set acl acl-filter {iface} type ipv6 entry 100 description DenyICMPv6All")
        commands.append(f"set acl acl-filter {iface} type ipv6 entry 100 match ipv6 next-header icmp6")
        commands.append(f"set acl acl-filter {iface} type ipv6 entry 100 action log true drop")
        commands.append(f"set acl interface {iface} input acl-filter {iface} type ipv6")
        commands.append(f"set acl acl-filter {iface} type ipv6 statistics-per-entry true")
        commands.append(f"set acl acl-filter {iface} type ipv6 subinterface-specific input-only")
       
    commands.append("commit stay")

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cli",
        "params": {"commands": commands}
    }

    json_payload = json.dumps(payload)

    curl_command = [
        "curl", "-k", "-u", f"{SRL_USER}:{SRL_PASS}",
        "-X", "POST", SRL_URL,
        "-H", "Content-Type: application/json",
        "-d", json_payload
    ]

    print(f"[*] Enviando ACLs ({len(commands)} comandos) al switch...")
    result = subprocess.run(curl_command, capture_output=True, text=True)
    print("=== Respuesta del servidor ===")
    print(result.stdout)
    print("=== STDERR ===")
    print(result.stderr)

    ultimo_acl_sentido = acl_hash

# Main loop
def main():
    print(f"[*] Iniciando monitoreo conjunto de ACLs y Elasticsearch cada {INTERVALO_SEGUNDOS}s...")

    while True:
        nuevos = leer_nuevos_bindings()

        if nuevos:
            print(f"[+] Nuevos bindings detectados: {len(nuevos)}")
            enviar_bulk_elasticsearch(nuevos)
            build_and_send_acls(nuevos)
        else:
            print("[=] Sin nuevos bindings válidos. No se envió nada.")

        time.sleep(INTERVALO_SEGUNDOS)

if __name__ == "__main__":
    main()
