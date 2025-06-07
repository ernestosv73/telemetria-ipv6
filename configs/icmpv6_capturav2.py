#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from datetime import datetime
import json
import signal
import sys
import os

# === Configuración ===
INTERFACE = "eth1"
CAPTURE_DURATION = 60  # segundos
MAC_UPDATES_FILE = "/data/mac_updates.json"
OUTPUT_DIR = "/data"

# === Variables globales ===
bindings = {}
mac_lookup = {}

# === Normalizar MAC ===
def normalize_mac(mac):
    return mac.lower().replace("-", ":").strip()

# === Extraer última tabla MAC del archivo JSON por líneas ===
def load_latest_mac_table():
    mac_table = {}

    try:
        with open(MAC_UPDATES_FILE, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if "updates" not in data:
                        continue

                    for update in data["updates"]:
                        path = update.get("Path", "")
                        if "mac[address=" in path:
                            mac_start = path.find("mac[address=") + len("mac[address=")
                            mac_end = path.find("]", mac_start)
                            mac = path[mac_start:mac_end].strip().lower()

                            mac = normalize_mac(mac)
                            values = update.get("values", {})
                            for key, val in values.items():
                                if val.get("type") != "learnt":
                                    continue
                                interface = val.get("destination", "unknown")
                                mac_table[mac] = interface
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Error al procesar archivo MAC updates: {e}")

    return mac_table

# === Procesar paquetes ICMPv6 NS/NA ===
def process_packet(pkt):
    if pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
        eth = pkt[Ether]
        ipv6 = pkt[IPv6]
        icmp = pkt.getlayer(ICMPv6ND_NS) or pkt.getlayer(ICMPv6ND_NA)

        src_mac = normalize_mac(eth.src)
        target_ip = icmp.tgt
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        if src_mac not in mac_lookup:
            return  # ignorar MACs no conocidas

        if src_mac not in bindings:
            bindings[src_mac] = {
                "mac": src_mac,
                "interface": mac_lookup[src_mac],
                "ipv6_link_local": None,
                "ipv6_global": None,
                "timestamp": timestamp
            }

        if target_ip.startswith("fe80::"):
            bindings[src_mac]["ipv6_link_local"] = target_ip
        else:
            bindings[src_mac]["ipv6_global"] = target_ip

        bindings[src_mac]["timestamp"] = timestamp

# === Timeout handler ===
def timeout_handler(signum, frame):
    print("\n[*] Tiempo de captura finalizado.")
    generate_output()
    sys.exit(0)

signal.signal(signal.SIGALRM, timeout_handler)

# === Escribir salida ===
def generate_output():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = f"{OUTPUT_DIR}/bindings_{timestamp}.json"
    with open(out_file, "w") as f:
        json.dump(list(bindings.values()), f, indent=2)
    print(f"[✅] Archivo generado: {out_file}")

# === MAIN ===
if __name__ == "__main__":
    print(f"[*] Cargando última tabla MAC desde '{MAC_UPDATES_FILE}'...")
    mac_lookup = load_latest_mac_table()
    print(f"[+] {len(mac_lookup)} entradas encontradas.")

    if not mac_lookup:
        print("[!] No hay datos en la tabla MAC. Abortando.")
        sys.exit(1)

    print(f"[*] Iniciando captura ICMPv6 en '{INTERFACE}' por {CAPTURE_DURATION} segundos...")
    signal.alarm(CAPTURE_DURATION)

    sniff(
        iface=INTERFACE,
        filter="icmp6",
        prn=process_packet,
        store=False
    )

    # Si se interrumpe manualmente
    generate_output()
