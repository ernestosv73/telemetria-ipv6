#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS
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
RELOAD_INTERVAL = 4  # segundos

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

# === Procesar paquetes ICMPv6 (solo RS y NS válidos) ===
def process_packet(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]
    ipv6 = pkt[IPv6]
    src_mac = eth.src.lower().replace("-", ":").strip()
    dst_mac = eth.dst.lower().replace("-", ":").strip()
    src_ip = ipv6.src
    timestamp = datetime.utcnow().isoformat()

    if src_mac not in mac_lookup:
        print(f"[DEBUG] MAC {src_mac} NO encontrada en mac_lookup")
        return

    iface = mac_lookup[src_mac]

    if src_mac not in bindings:
        bindings[src_mac] = {
            "mac": src_mac,
            "interface": iface,
            "ipv6_link_local": None,
            "ipv6_global": None,
            "timestamp": timestamp
        }

    updated = False

    # === Mensaje RS → usar source address como link-local ===
    if pkt.haslayer(ICMPv6ND_RS):
        if src_ip.startswith("fe80::"):
            print(f"[DEBUG] RS → Link-local detectada para {src_mac}: {src_ip}")
            bindings[src_mac]["ipv6_link_local"] = src_ip
            updated = True

    
    # === Mensaje NS → usar solo si es DAD válido ===
    elif pkt.haslayer(ICMPv6ND_NS):
    ip_target = pkt[ICMPv6ND_NS].tgt

    # Validar solo si target es una IPv6 global unicast
    if not ip_target.startswith("fe80::"):
        # Extraer últimos 24 bits (6 hex dígitos) de target IPv6
        target_suffix = ip_target.replace(":", "")[-6:].lower()
        
        # Extraer últimos 24 bits de dirección de destino (multicast)
        dst_ip_suffix = ipv6.dst.replace(":", "")[-6:].lower()

        if target_suffix != dst_ip_suffix:
            print(f"[DEBUG] NS descartado: sufijo target {target_suffix} ≠ destino {dst_ip_suffix}")
            return

        print(f"[DEBUG] NS válido (DAD) → Global detectada para {src_mac}: {ip_target}")
        bindings[src_mac]["ipv6_global"] = ip_target
        updated = True

    # Mensajes NA son ignorados

    if updated:
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
