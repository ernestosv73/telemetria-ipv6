import json
import time
import threading
from datetime import datetime
from scapy.all import sniff, IPv6, ICMPv6ND_NS
from collections import defaultdict
import os

# Tabla dinámica de bindings: MAC -> (interfaz, IPv6 link-local, global, timestamp)
bindings_table = {}
mac_table = {}

def load_mac_table_updates(path="/data/mac_updates.json"):
    """
    Hilo que monitorea mac_updates.json línea por línea
    y actualiza la tabla MAC en tiempo real.
    """
    print(f"[{datetime.now().isoformat()}] Iniciando monitoreo de tabla MAC")
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                data = json.loads(line.strip())
                for update in data.get("updates", []):
                    mac = update["values"]["mac-address"]
                    iface = update["values"].get("interface")
                    mac_table[mac] = iface
            except json.JSONDecodeError:
                print(f"[{datetime.now().isoformat()}] Línea no es JSON válido: {line.strip()}")
            except Exception as e:
                print(f"[{datetime.now().isoformat()}] Error procesando línea: {e}")

def capture_icmpv6(interface="eth1"):
    """
    Captura mensajes ICMPv6 Neighbor Solicitation en tiempo real,
    y los correlaciona con la tabla MAC actualizada.
    """
    print(f"[{datetime.now().isoformat()}] Iniciando captura de ICMPv6 en {interface}")
    def process_packet(pkt):
        if pkt.haslayer(ICMPv6ND_NS):
            src_mac = pkt.src
            src_ipv6 = pkt[IPv6].src
            iface = mac_table.get(src_mac, "unknown")

            entry = bindings_table.get(src_mac, {
                "mac": src_mac,
                "interface": iface,
                "ipv6_link_local": None,
                "ipv6_global": None,
                "last_seen": None
            })

            if src_ipv6.startswith("fe80"):
                entry["ipv6_link_local"] = src_ipv6
            else:
                entry["ipv6_global"] = src_ipv6

            entry["last_seen"] = datetime.now().isoformat()
            bindings_table[src_mac] = entry

    sniff(filter="icmp6 and ip6[40] == 135", prn=process_packet, iface=interface, store=0)

def write_bindings_periodically(output_path="/data/mac_ipv6_bindings_dynamic.json", interval=5):
    """
    Guarda la tabla de bindings correlacionada a un archivo JSON periódicamente.
    """
    print(f"[{datetime.now().isoformat()}] Escribiendo tabla a {output_path} cada {interval} segundos")
    while True:
        with open(output_path, "w") as f:
            json.dump(list(bindings_table.values()), f, indent=2)
        time.sleep(interval)

if __name__ == "__main__":
    t1 = threading.Thread(target=load_mac_table_updates, daemon=True)
    t2 = threading.Thread(target=capture_icmpv6, daemon=True)
    t3 = threading.Thread(target=write_bindings_periodically, daemon=True)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()
