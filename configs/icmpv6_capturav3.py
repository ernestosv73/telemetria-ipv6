#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_RS
from datetime import datetime
import json
import signal
import sys
import threading
import time
import re

# === Configuración ===
INTERFACE = "eth1"
OUTPUT_JSON = "/data/mac_ipv6_bindings_dynamic.json"
MAC_UPDATES_FILE = "/data/mac_updates.json"
RELOAD_INTERVAL = 4  # segundos

bindings = {}
mac_lookup = {}

# === Función para cargar tabla MAC ===
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

# === Recarga periódica de tabla MAC ===
def periodic_mac_reload():
    global mac_lookup
    while True:
        updated = load_mac_table_from_file(MAC_UPDATES_FILE)
        print(f"[INFO] Tabla MAC recargada. Entradas: {len(updated)}")
        mac_lookup = updated
        time.sleep(RELOAD_INTERVAL)

# === Guardar bindings a JSON (una entrada por dirección global) ===
def save_bindings():
    output = []
    for mac, b in bindings.items():
        if b["ipv6_global"]:
            for ip, ts in b["ipv6_global"].items():
                entry = {
                    "mac": mac,
                    "interface": b["interface"],
                    "ipv6_link_local": b["ipv6_link_local"],
                    "ipv6_global": ip,
                    "timestamp": ts
                }
                output.append(entry)
        else:
            entry = {
                "mac": mac,
                "interface": b["interface"],
                "ipv6_link_local": b["ipv6_link_local"],
                "ipv6_global": None,
                "timestamp": datetime.utcnow().isoformat()
            }
            output.append(entry)
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(output, f, indent=2)

# === Heurística para identificar stable vs temporal ===
def is_stable_ipv6(ip):
    # RFC 7217 IID suele ser estable y no aleatoria (heurística simple)
    # Temporal (RFC 4941) suele tener bits de IID aleatorios => no 0:0:0:...
    # Simple: si el último bloque tiene un patrón aleatorio (no 0) → temporal
    last_block = ip.split(":")[-1]
    return not re.match(r"^[0]{0,4}[0-9a-f]{0,4}$", last_block)

# === Procesar paquetes ICMPv6 ===
def process_packet(pkt):
    if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]
    ipv6 = pkt[IPv6]
    src_mac = eth.src.lower().replace("-", ":").strip()

    if src_mac not in mac_lookup:
        print(f"[DEBUG] MAC {src_mac} NO encontrada en mac_lookup")
        return

    iface = mac_lookup[src_mac]
    timestamp = datetime.utcnow().isoformat()

    if src_mac not in bindings:
        bindings[src_mac] = {
            "interface": iface,
            "ipv6_link_local": None,
            "ipv6_global": {}
        }

    updated = False

    # === RS → link-local ===
    if pkt.haslayer(ICMPv6ND_RS) and ipv6.src.startswith("fe80::"):
        if bindings[src_mac]["ipv6_link_local"] != ipv6.src:
            bindings[src_mac]["ipv6_link_local"] = ipv6.src
            updated = True

    # === NS → DAD, global ===
    elif pkt.haslayer(ICMPv6ND_NS):
        ip_target = pkt[ICMPv6ND_NS].tgt
        if ipv6.src == "::" and ipv6.dst.lower().startswith("ff02::1:ff"):
            if not ip_target.startswith("fe80::"):
                stable = is_stable_ipv6(ip_target)
                key = ip_target
                if key not in bindings[src_mac]["ipv6_global"]:
                    bindings[src_mac]["ipv6_global"][key] = timestamp
                    updated = True
            else:
                print(f"[DEBUG] NS descartado: target {ip_target} es link-local")
        else:
            print(f"[DEBUG] NS descartado: no cumple condiciones DAD (src={ipv6.src}, dst={ipv6.dst})")

    if updated:
        save_bindings()

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
