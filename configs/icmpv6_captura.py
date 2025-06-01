#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS
from datetime import datetime
import json
import subprocess
import os
import signal
import sys

# === Configuración ===
INTERFACE = "eth1"
CAPTURE_DURATION = 20
OUTPUT_JSON = "/data/mac_ipv6_bindings.json"
OUTPUT_DIR = "/data"

GNMI_TARGET = "srlswitch:57400"
GNMI_USER = "admin"
GNMI_PASS = "NokiaSrl1!"
GNMI_PATH = '/network-instance[name=lanswitch]/bridge-table/mac-table/mac'

# === Preparar directorio de salida ===
os.makedirs(OUTPUT_DIR, exist_ok=True)
bindings = {}

# === Procesar paquetes ICMPv6 Neighbor Solicitation ===
def process_packet(pkt):
    if pkt.haslayer(ICMPv6ND_NS):
        eth_layer = pkt[Ether]
        ns_layer = pkt[ICMPv6ND_NS]
        mac = eth_layer.src.lower()
        target_ip = ns_layer.tgt
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        is_link_local = target_ip.startswith("fe80::")

        if mac not in bindings:
            bindings[mac] = {
                "mac": mac,
                "interface": "unknown",
                "ipv6_link_local": None,
                "ipv6_global": None,
                "timestamp": timestamp
            }

        if is_link_local:
            bindings[mac]["ipv6_link_local"] = target_ip
        else:
            bindings[mac]["ipv6_global"] = target_ip

        bindings[mac]["timestamp"] = timestamp

# === Obtener tabla MAC desde SR Linux vía gNMI ===
def get_mac_table():
    cmd = [
        "gnmic", "-a", GNMI_TARGET, "--skip-verify",
        "-u", GNMI_USER, "-p", GNMI_PASS,
        "-e", "json_ietf",
        "get", "--path", GNMI_PATH
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = json.loads(result.stdout)
        mac_entries = output[0]['updates'][0]['values'][
            "srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table"
        ]["mac"]
        return mac_entries
    except Exception as e:
        print(f"[!] Error al obtener tabla MAC: {e}")
        return []

# === Normalizar formato de MAC ===
def normalize_mac(mac):
    return mac.lower().replace("-", ":").strip()

# === Correlacionar MAC ↔ Interfaz ===
def correlate_with_gnmi(mac_bindings, mac_table):
    lookup = {
        normalize_mac(entry["address"]): entry["destination"]
        for entry in mac_table
    }

    count = 0
    for mac in mac_bindings:
        norm_mac = normalize_mac(mac)
        if norm_mac in lookup:
            mac_bindings[mac]["interface"] = lookup[norm_mac]
            count += 1
    return count

# === Timeout ===
def handler(signum, frame):
    print("\n[*] Tiempo de captura terminado.")
    finish()

signal.signal(signal.SIGALRM, handler)

# === Escribir resultado JSON ===
def generate_output():
    with open(OUTPUT_JSON, "w") as f:
        json.dump(list(bindings.values()), f, indent=2)
    print(f"[✅] Archivo generado: {OUTPUT_JSON}")

def finish():
    matched = correlate_with_gnmi(bindings, mac_table)
    total = len(bindings)
    print(f"\n[✓] {matched} de {total} MACs correlacionadas con interfaz")
    generate_output()
    sys.exit(0)

# === MAIN ===
if __name__ == "__main__":
    print("[*] Obteniendo tabla MAC desde SR Linux...")
    mac_table = get_mac_table()
    print(f"[+] {len(mac_table)} entradas obtenidas de la tabla MAC")

    # DEBUG: MACs del SR Linux
    print("\n[DEBUG] MACs en tabla gNMI:")
    for entry in mac_table:
        print(f" - {entry['address']} => {entry['destination']}")

    print(f"[*] Capturando tráfico ICMPv6 Neighbor Solicitation en '{INTERFACE}' durante {CAPTURE_DURATION} segundos...")
    signal.alarm(CAPTURE_DURATION)

    sniff(
        iface=INTERFACE,
        filter="icmp6",
        prn=process_packet,
        store=False
    )

    # Si termina manualmente antes del timeout
    print("\n[DEBUG] MACs capturadas:")
    for m in bindings:
        print(f" - {m}")

    finish()
