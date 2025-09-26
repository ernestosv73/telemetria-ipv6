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

# Estructura principal: usar set para ipv6_globals
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
                    if "updates" in 
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
        # Convertir set a lista y eliminar duplicados
        globals_clean = list(set(b["ipv6_globals"]))
        if b["ipv6_link_local"] or globals_clean:
            cleaned = {
                "mac": b["mac"],
                "interface": b["interface"],
                "ipv6_link_local": b["ipv6_link_local"],
                "ipv6_globals": globals_clean,
                "timestamp": b["timestamp"]
            }
            valid.append(cleaned)

    with open(OUTPUT_JSON, 'w') as f:
        json.dump(valid, f, indent=2)

    print(f"[SAVE] {len(valid)} hosts guardados con {sum(len(v['ipv6_globals']) for v in valid)} direcciones globales")

# === Clasificar si una dirección IPv6 es global ===
def is_global_ipv6(ip):
    return not ip.startswith("fe80::") and not ip.startswith("ff") and ":" in ip

# === Procesar paquetes ICMPv6 ===
def process_packet(pkt):
    global bindings

    if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]
    ipv6 = pkt[IPv6]
    src_mac = eth.src.lower().replace("-", ":").strip()
    src_ip = ipv6.src
    dst_ip = ipv6.dst
    timestamp = datetime.utcnow().isoformat()

    # Verificar si MAC está en tabla MAC del switch
    if src_mac not in mac_lookup:
        print(f"[DEBUG] MAC {src_mac} NO encontrada en mac_lookup")
        return

    iface = mac_lookup[src_mac]

    # Inicializar entrada si no existe
    if src_mac not in bindings:
        bindings[src_mac] = {
            "mac": src_mac,
            "interface": iface,
            "ipv6_link_local": None,
            "ipv6_globals": [],  # Seguimos usando lista por simplicidad
            "timestamp": timestamp
        }

    updated = False

    # === 1. Mensaje RS → actualizar link-local si es válido ===
    if pkt.haslayer(ICMPv6ND_RS):
        if src_ip.startswith("fe80::"):
            print(f"[DEBUG] RS → Link-local detectada para {src_mac}: {src_ip}")
            bindings[src_mac]["ipv6_link_local"] = src_ip
            updated = True

    # === 2. Mensaje NS → DAD (Dirección global o link-local) ===
    elif pkt.haslayer(ICMPv6ND_NS):
        tgt_ip = pkt[ICMPv6ND_NS].tgt

        # Condición de DAD: src = ::, dst = ff02::1:ffXX:XXXX
        if src_ip == "::" and dst_ip.lower().startswith("ff02::1:ff"):
            if is_global_ipv6(tgt_ip):
                if tgt_ip not in bindings[src_mac]["ipv6_globals"]:
                    print(f"[DEBUG] NS (DAD) → Nueva dirección GLOBAL detectada: {tgt_ip} para {src_mac}")
                    bindings[src_mac]["ipv6_globals"].append(tgt_ip)
                    updated = True
                else:
                    print(f"[DEBUG] NS (DAD) → Dirección global ya registrada: {tgt_ip}")
            else:
                print(f"[DEBUG] NS (DAD) → Ignorado: target {tgt_ip} no es global")

    # === 3. Mensaje NA → puede confirmar una dirección global ===
    elif pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        tgt_ip = na.tgt

        # Solo procesar NA no-solicited (confirmación de DAD) o unicast
        if na.R == 0 and is_global_ipv6(tgt_ip):  # R=0 → no es redirección
            if tgt_ip not in bindings[src_mac]["ipv6_globals"]:
                print(f"[DEBUG] NA → Confirmación de dirección GLOBAL: {tgt_ip} para {src_mac}")
                bindings[src_mac]["ipv6_globals"].append(tgt_ip)
                updated = True
            else:
                print(f"[DEBUG] NA → Dirección global ya conocida: {tgt_ip}")

    # Actualizar timestamp si hubo cambios
    if updated:
        bindings[src_mac]["timestamp"] = timestamp
        print(f"[DEBUG] Binding actualizado para {src_mac}: {bindings[src_mac]}")
        save_bindings()  # guardar inmediatamente tras cambio

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
