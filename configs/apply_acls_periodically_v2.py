#!/usr/bin/env python3

import json
import subprocess
import time
from collections import defaultdict
from pathlib import Path

bindings_file = "/data/mac_ipv6_bindings_dynamic.json"
interval = 30  # segundos
last_sent_bindings = None  # Se guarda la última versión enviada


def is_complete_entry(entry):
    return all([
        entry.get("mac"),
        entry.get("interface"),
        entry.get("ipv6_link_local"),
        entry.get("ipv6_global")
    ])


def build_and_send_acls(bindings):
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

    print(f"[*] Enviando {len(commands)} comandos al switch...")
    result = subprocess.run(curl_command, capture_output=True, text=True)
    print("=== Respuesta del servidor ===")
    print(result.stdout)
    print("=== STDERR ===")
    print(result.stderr)


def bindings_changed(new_bindings, previous_bindings):
    if previous_bindings is None:
        return True
    new_sorted = json.dumps(new_bindings, sort_keys=True)
    old_sorted = json.dumps(previous_bindings, sort_keys=True)
    return new_sorted != old_sorted


def main():
    global last_sent_bindings
    print("[*] Iniciando monitoreo periódico de bindings...")
    while True:
        if Path(bindings_file).exists():
            try:
                with open(bindings_file, "r") as f:
                    bindings = json.load(f)

                complete_bindings = [e for e in bindings if is_complete_entry(e)]

                if complete_bindings:
                    if bindings_changed(complete_bindings, last_sent_bindings):
                        print(f"[+] Se encontraron {len(complete_bindings)} bindings nuevos. Enviando ACLs.")
                        build_and_send_acls(complete_bindings)
                        last_sent_bindings = complete_bindings
                    else:
                        print("[=] Los bindings no cambiaron. No se enviaron ACLs.")
                else:
                    print("[-] No se encontraron bindings completos. Esperando...")

            except Exception as e:
                print(f"[!] Error procesando el archivo: {e}")
        else:
            print(f"[!] El archivo '{bindings_file}' no existe.")

        time.sleep(interval)


if __name__ == "__main__":
    main()
