import json
import time
from datetime import datetime
from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
import threading

# === Configuración ===
INTERFACE = "eth1"  # Interfaz donde capturar ICMPv6
MAC_UPDATES_FILE = "/data/mac_updates.json"
OUTPUT_JSON = "/data/mac_ipv6_bindings_dynamic.json"
POLL_INTERVAL = 5  # segundos para leer cambios en mac_updates.json

# === Variables globales ===
mac_table = {}  # { mac: { interface, timestamp } }
bindings = {}   # { mac: { mac, interface, ipv6_link_local, ipv6_global, timestamp } }

# === Función: Leer archivo mac_updates.json ===
def actualizar_tabla_mac():
    global mac_table
    try:
        with open(MAC_UPDATES_FILE, "r") as f:
            content = f.read().strip()
        
        if not content:
            print(f"[{datetime.now().isoformat()}] Archivo vacío: {MAC_UPDATES_FILE}")
            return

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

                        mac_table[normalized_mac] = {
                            "interface": interface,
                            "timestamp": datetime.now().isoformat()
                        }

            except json.JSONDecodeError as je:
                print(f"[{datetime.now().isoformat()}] Error decodificando bloque JSON: {je}")
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Error leyendo archivo: {e}")

# === Función: Leer tabla MAC periódicamente ===
def monitorear_archivo_mac():
    while True:
        actualizar_tabla_mac()
        time.sleep(POLL_INTERVAL)

# === Función: Procesar paquetes ICMPv6 ===
def procesar_paquete(pkt):
    if not (pkt.haslayer(Ether) and pkt.haslayer(IPv6) and (pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA))):
        return

    eth_src = pkt[Ether].src.lower()
    ipv6_addr = pkt[IPv6].src
    timestamp = datetime.utcnow().isoformat()

    # Inicializar si no existe
    if eth_src not in bindings:
        bindings[eth_src] = {
            "mac": eth_src,
            "interface": mac_table.get(eth_src, {}).get("interface", "unknown"),
            "ipv6_link_local": None,
            "ipv6_global": None,
            "timestamp": timestamp
        }

    is_link_local = ipv6_addr.startswith("fe80::")

    if is_link_local:
        bindings[eth_src]["ipv6_link_local"] = ipv6_addr
    else:
        bindings[eth_src]["ipv6_global"] = ipv6_addr

    bindings[eth_src]["timestamp"] = timestamp

# === Función: Capturar tráfico ICMPv6 ===
def capturar_icmpv6():
    print(f"[{datetime.now().isoformat()}] Iniciando captura ICMPv6 en {INTERFACE}")
    sniff(iface=INTERFACE, filter="icmp6", prn=procesar_paquete, store=False)

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

    t1.join()
    t2.join()
    t3.join()
