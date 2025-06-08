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
mac_lookup = {}

# === Cargar tabla MAC desde archivo ===
def load_mac_table_from_file(file_path):
    entries = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if "updates" in data:
                        for update in data["updates"]:
                            path = update["Path"]
                            if "mac[address=" in path:
                                mac = path.split("mac[address=")[1].split("]")[0]
                                mac = mac.lower().replace("-", ":").strip()
                                destination = update["values"][
                                    "srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table/mac"
                                ]["destination"]
                                entries[mac] = destination
                    elif "deletes" in data:
                        for deleted_path in data["deletes"]:
                            if "mac[address=" in deleted_path:
                                mac = deleted_path.split("mac[address=")[1].split("]")[0]
                                mac = mac.lower().replace("-", ":").strip()
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

        print(f"[DEBUG] Paquete ICMPv6 recibido de MAC: {src_mac}, IP: {src_ip}")

        if src_mac not in mac_lookup:
            print(f"[DEBUG] MAC {src_mac} NO encontrada en mac_lookup")
            print(f"[DEBUG] MACs disponibles: {list(mac_lookup.keys())}")
            return
        else:
            print(f"[DEBUG] MAC {src_mac} encontrada. Procesando binding...")

        iface = mac_lookup[src_mac]
        is_link_local = pkt[ICMPv6ND_NS].tgt.startswith("fe80::") if pkt.haslayer(ICMPv6ND_NS) else pkt[ICMPv6ND_NA].tgt.startswith("fe80::")
        ip_target = pkt[ICMPv6ND_NS].tgt if pkt.haslayer(ICMPv6ND_NS) else pkt[ICMPv6ND_NA].tgt
        timestamp = datetime.utcnow().isoformat()

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

        with open(OUTPUT_JSON, 'w') as f:
            json.dump(list(bindings.values()), f, indent=2)

# === Manejador de señales ===
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

    print("[*] Lista de MACs cargadas:")
    for mac, iface in mac_lookup.items():
        print(f"  {mac} -> {iface}")

    signal.signal(signal.SIGINT, signal_handler)
    print(f"[*] Iniciando captura en {INTERFACE} (Ctrl+C para detener)...")
    sniff(iface=INTERFACE, filter="icmp6", prn=process_packet, store=0)
