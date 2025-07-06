#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from datetime import datetime
import json
import os
import signal
import sys
import threading
import time

# === Configuración ===
INTERFACE = "eth1"
OUTPUT_JSON = "/data/mac_ipv6_bindings_dynamic.json"
MAC_UPDATES_FILE = "/data/mac_updates.json"
RELOAD_INTERVAL = 2  # segundos

bindings = {}
mac_lookup = {}

# === Cargar tabla MAC desde archivo (solo 'updates') ===
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
                    # Ignorar completamente 'deletes'
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Error leyendo {file_path}: {e}")
    return entries

# === Recarga periódica de la tabla MAC ===
def periodic_mac_reload():
    global mac_lookup
    while True:
        updated = load_mac_table_from_file(MAC_UPDATES_FILE)
        print(f"[INFO] Tabla MAC recargada. Entradas: {len(updated)}")
        mac_lookup = updated
        time.sleep(RELOAD_INTERVAL)

# === Guardar bindings válidos en archivo ===
def save_bindings():
    valid = [
        b for b in bindings.values()
        if b["ipv6_link_local"] or b["ipv6_global"]
    ]
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(valid, f, indent=2)

# === Procesar paquetes ICMPv6 NS y NA ===
def process_packet(pkt):
    if pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
        eth = pkt[Ether]
        ipv6 = pkt[IPv6]
        src_mac = eth.src.lower().replace("-", ":").strip()
        dst_mac = eth.dst.lower().replace("-", ":").strip()
        src_ip = ipv6.src

        if pkt.haslayer(ICMPv6ND_NS):
            if dst_mac.startswith("33:33:ff"):
                src_mac_suffix = src_mac.split(":")[-3:]
                dst_mac_suffix = dst_mac.split(":")[-3:]
                if src_mac_suffix != dst_mac_suffix:
                    print(f"[DEBUG] NS no válido para binding: src_mac {src_mac} vs dst_mac {dst_mac}")
                    return

        print(f"[DEBUG] Paquete ICMPv6 recibido de MAC: {src_mac}, IP: {src_ip}")

        if src_mac not in mac_lookup:
            print(f"[DEBUG] MAC {src_mac} NO encontrada en mac_lookup")
            print(f"[DEBUG] MACs disponibles: {list(mac_lookup.keys())}")
            return
        else:
            print(f"[DEBUG] MAC {src_mac} encontrada. Procesando binding...")

        iface = mac_lookup[src_mac]
        ip_target = pkt[ICMPv6ND_NS].tgt if pkt.haslayer(ICMPv6ND_NS) else pkt[ICMPv6ND_NA].tgt
        is_link_local = ip_target.startswith("fe80::")
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
        print(f"[DEBUG] Binding actualizado para {src_mac}: {bindings[src_mac]}")

        with open(OUTPUT_JSON, 'w') as f:
            json.dump(list(bindings.values()), f, indent=2)

# === Manejador de señales ===
def signal_handler(sig, frame):
    print("\n[*] Captura detenida. Guardando archivo final...")
    save_bindings()
    sys.exit(0)

# === Main ===
if __name__ == "__main__":
    print("[*] Iniciando recarga dinámica de tabla MAC...")
    threading.Thread(target=periodic_mac_reload, daemon=True).start()

    signal.signal(signal.SIGINT, signal_handler)
    print(f"[*] Iniciando captura en {INTERFACE} (Ctrl+C para detener)...")
    sniff(iface=INTERFACE, filter="icmp6", prn=process_packet, store=0)
