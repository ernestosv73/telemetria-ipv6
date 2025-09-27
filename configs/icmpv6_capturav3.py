#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_RS
from datetime import datetime
import json
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
    valid = []
    for b in bindings.values():
        if b["ipv6_global"]:
            for ip in b["ipv6_global"]:
                entry = {
                    "mac": b["mac"],
                    "interface": b["interface"],
                    "ipv6_link_local": b["ipv6_link_local"],
                    "ipv6_global": ip,
                    "timestamp": b["timestamp"]
                }
                valid.append(entry)
        else:
            entry = {
                "mac": b["mac"],
                "interface": b["interface"],
                "ipv6_link_local": b["ipv6_link_local"],
                "ipv6_global": None,
                "timestamp": b["timestamp"]
            }
            valid.append(entry)
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(valid, f, indent=2)

# === Procesar paquetes ICMPv6 (RS y NS) ===
def process_packet(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]
    ipv6 = pkt[IPv6]
    src_mac = eth.src.lower().replace("-", ":").strip()
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
            "ipv6_global": [],
            "timestamp": timestamp
        }

    updated = False

    # === RS → source address link-local ===
    if pkt.haslayer(ICMPv6ND_RS):
        if ipv6.src.startswith("fe80::"):
            if bindings[src_mac]["ipv6_link_local"] != ipv6.src:
                print(f"[DEBUG] RS → Link-local detectada para {src_mac}: {ipv6.src}")
                bindings[src_mac]["ipv6_link_local"] = ipv6.src
                updated = True

    # === NS → válido solo si es DAD (RFC 4862) ===
    elif pkt.haslayer(ICMPv6ND_NS):
        ip_target = pkt[ICMPv6ND_NS].tgt

        # DAD conditions
        if ipv6.src == "::" and ipv6.dst.lower().startswith("ff02::1:ff"):
            if not ip_target.startswith("fe80::"):
                if ip_target not in bindings[src_mac]["ipv6_global"]:
                    print(f"[DEBUG] NS válido (DAD) → Global detectada para {src_mac}: {ip_target}")
                    bindings[src_mac]["ipv6_global"].append(ip_target)
                    updated = True
            else:
                print(f"[DEBUG] NS descartado: target {ip_target} es link-local")
        else:
            print(f"[DEBUG] NS descartado: no cumple condiciones DAD (src={ipv6.src}, dst={ipv6.dst})")

    if updated:
        bindings[src_mac]["timestamp"] = timestamp
        save_bindings()  # guarda inmediatamente tras actualizar

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
