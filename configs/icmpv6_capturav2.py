#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from datetime import datetime
import json
import os
import signal
import sys

# === Configuración ===
INTERFACE = "eth1"
OUTPUT_JSON = "/data/mac_ipv6_bindings_dynamic.json"
MAC_UPDATES_FILE = "/data/mac_updates.json"

bindings = {}
mac_table = []
mac_lookup = {}

# === Cargar tabla MAC desde archivo ===
def load_mac_table_from_file(file_path):
    entries = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())

                    # Procesar solo updates válidos
                    if "updates" in data:
                        for update in data["updates"]:
                            path = update["Path"]
                            if "mac[address=" in path:
                                mac = path.split("mac[address=")[1].split("]")[0]
                                mac = mac.lower().replace("-", ":")
                                destination = update["values"][
                                    "srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table/mac"
                                ]["destination"]
                                entries[mac] = destination
                    elif "deletes" in data:
                        for deleted_path in data["deletes"]:
                            if "mac[address=" in deleted_path:
                                mac = deleted_path.split("mac[address=")[1].split("]")[0]
                                mac = mac.lower().replace("-", ":")
                                entries.pop(mac, None)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Error leyendo {file_path}: {e}")
    return entries

# === Procesar paquetes ICMPv6 NS y NA ===
def process_packet(pkt):
    if pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
        eth = pkt[Ether]
        ipv6 = pkt[IPv6]
        src_mac = eth.src.lower().replace("-", ":").strip()
        src_ip = ipv6.src

        # Determinar dirección de destino según tipo
        if pkt.haslayer(ICMPv6ND_NS):
            ip_target = pkt[ICMPv6ND_NS].tgt
        elif pkt.haslayer(ICMPv6ND_NA):
            ip_target = pkt[ICMPv6ND_NA].tgt
        else:
            return

        # Filtrar MACs no conocidas
        if src_mac not in mac_lookup:
            return

        iface = mac_lookup[src_mac]
        is_link_local = ip_target.startswith("fe80::")
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        if src_mac not in bindings:
            bindings[src_mac] = {
                "mac": src_mac,
                "interface": iface,
                "ipv6_link_local": None,
                "ipv6_global": None,
                "timestamp": timestamp
            }

        if is_link_local:
            bindings[src_mac]["ipv6_link_local"] = ip_target
        else:
            bindings[src_mac]["ipv6_global"] = ip_target

        bindings[src_mac]["timestamp"] = timestamp

        # Guardar en disco tras cada actualización
        with open(OUTPUT_JSON, 'w') as f:
            json.dump(list(bindings.values()), f, indent=2)

# === Manejador de señales para detener captura con Ctrl+C ===
def signal_handler(sig, frame):
    print("\n[*] Captura detenida. Guardando archivo final...")
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(list(bindings.values()), f, indent=2)
    sys.exit(0)

# === Main ===
if __name__ == "__main__":
    print("[*] Cargando tabla MAC desde archivo...")
    mac_lookup = load_mac_table_from_file(MAC_UPDATES_FILE)
    print(f"[*] MACs activas cargadas: {len(mac_lookup)}")

    if not mac_lookup:
        print("[!] Tabla MAC vacía. Verifica el archivo mac_updates.json.")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    print(f"[*] Iniciando captura en {INTERFACE} (Ctrl+C para detener)...")
    sniff(iface=INTERFACE, filter="icmp6", prn=process_packet, store=0)
