#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6
from datetime import datetime
import json
import os
import threading
import time

# === Configuración ===
INTERFACE = "eth1"  # Interfaz donde capturar ICMPv6
MAC_UPDATES_FILE = "/data/mac_updates.json"
OUTPUT_JSON = "/data/mac_ipv6_bindings_dynamic.json"
POLL_INTERVAL = 5  # segundos para leer cambios en mac_updates.json

# === Variables globales ===
bindings = {}          # { mac: { mac, interface, ipv6_link_local, ipv6_global, timestamp } }
mac_table = {}         # { normalized_mac: destination }

# === Función: Leer archivo mac_updates.json ===
def actualizar_tabla_mac():
    global mac_table
    try:
        with open(MAC_UPDATES_FILE, "r") as f:
            content = f.read().strip()

        if not content:
            print(f"[{datetime.now().isoformat()}] Archivo vacío: {MAC_UPDATES_FILE}")
            return

        mac_table.clear()
        for block in content.strip().split("\n"):
            if not block.startswith("{"):
                continue
            try:
                data = json.loads(block)
                if "updates" not in data:
                    continue

                for update in data["updates"]:
                    path = update.get("Path", "")
                    if "mac[address=" in path:
                        mac_address = path.split("mac[address=")[-1].rstrip("]")
                        normalized_mac = mac_address.lower()

                        values = update.get("values", {})
                        mac_info = values.get(
                            "srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table/mac",
                            {}
                        )
                        interface = mac_info.get("destination", "unknown")
                        if "reserved" in interface.lower():
                            continue

                        mac_table[normalized_mac] = interface

            except json.JSONDecodeError:
                print(f"[{datetime.now().isoformat()}] Línea no es JSON válido: {block}")
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Error leyendo archivo: {e}")

# === Función: Monitorear archivo de MACs ===
def monitorear_archivo_mac():
    while True:
        actualizar_tabla_mac()
        time.sleep(POLL_INTERVAL)

# === Función: Procesar paquetes ICMPv6 ===
def procesar_paquete(pkt):
    try:
        if not pkt.haslayer(Ether) or not pkt.haslayer(IPv6):
            return

        eth_layer = pkt[Ether]
        ipv6_layer = pkt[IPv6]

        eth_src = eth_layer.src.lower()
        ipv6_addr = ipv6_layer.src

        # Descartar direcciones IPv6 inválidas
        if ipv6_addr == "::":
            return

        timestamp = datetime.utcnow().isoformat()

        # Inicializar si no existe
        if eth_src not in bindings:
            interface = mac_table.get(eth_src, "unknown")
            bindings[eth_src] = {
                "mac": eth_src,
                "interface": interface,
                "ipv6_link_local": None,
                "ipv6_global": None,
                "timestamp": timestamp
            }

        is_link_local = ipv6_addr.startswith("fe80::")

        if is_link_local:
            if not bindings[eth_src]["ipv6_link_local"]:
                bindings[eth_src]["ipv6_link_local"] = ipv6_addr
        else:
            if not bindings[eth_src]["ipv6_global"]:
                bindings[eth_src]["ipv6_global"] = ipv6_addr

        bindings[eth_src]["timestamp"] = timestamp

    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Error procesando paquete: {e}")

# === Función: Capturar tráfico ICMPv6 en tiempo real ===
def capturar_icmpv6():
    print(f"[{datetime.now().isoformat()}] Iniciando captura ICMPv6 en {INTERFACE}")
    # Filtro: Neighbor Solicitation (135) y Advertisement (136)
    sniff(
        iface=INTERFACE,
        filter="icmp6 && ip6[40] == 135 or icmp6 && ip6[40] == 136",
        prn=procesar_paquete,
        store=False
    )

# === Función: Guardar bindings periódicamente ===
def guardar_periodicamente(intervalo):
    while True:
        try:
            with open(OUTPUT_JSON, "w") as f:
                json.dump(list(bindings.values()), f, indent=2)
            print(f"[{datetime.now().isoformat()}] Escribiendo bindings a {OUTPUT_JSON}")
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Error al guardar archivo: {e}")
        time.sleep(intervalo)

# === Main ===
if __name__ == "__main__":
    print(f"[{datetime.now().isoformat()}] Iniciando sistema de correlación MAC-IPv6")

    t1 = threading.Thread(target=monitorear_archivo_mac)
    t2 = threading.Thread(target=capturar_icmpv6)
    t3 = threading.Thread(target=guardar_periodicamente, args=(POLL_INTERVAL,))

    t1.start()
    t2.start()
    t3.start()

    try:
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        print(f"[{datetime.now().isoformat()}] Deteniendo script...")
