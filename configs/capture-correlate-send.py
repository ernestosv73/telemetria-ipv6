#!/usr/bin/env python3

import pyshark
import json
import time
from datetime import datetime
import subprocess
import jq
import requests

# === Parámetros ===
INTERFACE = "eth1"
ES_URL = "http://es01:9200"
INDEX_NAME = f"mac-ipv6-{datetime.utcnow().strftime('%Y.%m.%d')}"
OUTPUT_JSON = "/data/mac_ipv6_bindings.json"

# === Función: Obtener tabla MAC desde gNMI ===
def get_mac_table():
    cmd = [
        "gnmic", "-a", "srlswitch:57400", "--skip-verify",
        "-u", "admin", "-p", "NokiaSrl1!",
        "-e", "json_ietf",
        "get", "--path", "/network-instance[name=lanswitch]/bridge-table/mac-table/mac"
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print("[!] Error obteniendo tabla MAC")
        return []

    try:
        data = json.loads(result.stdout)
        mac_entries = []
        for response in data:
            values = response.get("updates", [{}])[0].get("values", {})
            entries = values.get("srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table", {}).get("mac", [])
            for entry in entries:
                if entry.get("type") == "learnt":
                    mac = entry["address"].lower()
                    intf = entry["destination"]
                    mac_entries.append({"mac": mac, "interface": intf})
        return mac_entries
    except Exception as e:
        print(f"[!] Error parseando tabla MAC: {e}")
        return []

# === Función: Procesar paquetes ICMPv6 ===
def process_ndp_packets(capture):
    known_macs = set()
    bindings = []

    for packet in capture.sniff_continuously(packet_count=50):  # procesa cada 50 paquetes
        try:
            eth_layer = packet.eth
            icmpv6_layer = packet.icmpv6

            src_mac = eth_layer.src.lower()
            target_address = icmpv6_layer.nd_target_address

            if not target_address:
                continue

            if src_mac not in known_macs:
                binding = {
                    "mac": src_mac,
                    "ipv6_link_local": "",
                    "ipv6_global": "",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }

                if target_address.startswith("fe80"):
                    binding["ipv6_link_local"] = target_address
                else:
                    binding["ipv6_global"] = target_address

                bindings.append(binding)
                known_macs.add(src_mac)
                print(f"[+] Nuevo host: {src_mac} -> {target_address}")

        except AttributeError:
            continue
        except Exception as e:
            print(f"[!] Error procesando paquete: {e}")
            continue

    return bindings

# === Función: Correlacionar MACs aprendidas con IPv6 ===
def correlate_bindings(bindings, mac_table):
    correlated = []

    for binding in bindings:
        src_mac = binding["mac"]
        matched = next((entry for entry in mac_table if entry["mac"] == src_mac), None)

        if matched:
            binding["interface"] = matched["interface"]
            correlated.append(binding)

    return correlated

# === Función: Guardar en disco y enviar a ES ===
def save_and_send_to_es(bindings):
    if not bindings:
        print("[*] No hay nuevos bindings para guardar")
        return

    # Guardar bindings en archivo JSON
    with open(OUTPUT_JSON, "w") as f:
        json.dump(bindings, f, indent=2)

    print(f"[+] Archivo generado: {OUTPUT_JSON}")

    # Preparar datos para Elasticsearch
    bulk_data = ""
    for doc in bindings:
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(doc) + "\n"

    # Enviar a Elasticsearch
    try:
        res = requests.post(
            f"{ES_URL}/{INDEX_NAME}/_bulk",
            headers={"Content-Type": "application/json"},
            data=bulk_data
        )
        print(f"[+] Datos enviados a índice '{INDEX_NAME}' → {res.status_code}")
    except Exception as e:
        print(f"[!] Error enviando datos a Elasticsearch: {e}")

# === Función principal ===
def main():
    print("[*] Iniciando captura de tráfico ICMPv6...")
    
    while True:
        # 1. Capturar tráfico NDP en tiempo real
        capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="icmpv6.type == 135 or icmpv6.type == 136")

        # 2. Procesar paquetes y obtener bindings MAC-IPv6
        bindings = process_ndp_packets(capture)

        # 3. Obtener tabla MAC actual
        mac_table = get_mac_table()

        # 4. Correlacionar con interfaz física
        correlated_bindings = correlate_bindings(bindings, mac_table)

        # 5. Guardar y enviar a Elasticsearch
        save_and_send(bindings)

        # Esperar antes de nueva corrida
        print("[*] Reiniciando captura en 10 segundos...")
        time.sleep(10)

# === Iniciar ===
if __name__ == "__main__":
    main()
