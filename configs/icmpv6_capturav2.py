import json
import time
import threading
import queue
from scapy.all import sniff, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, get_if_hwaddr

# Ruta al archivo mac_updates.json (en modo append)
MAC_UPDATES_FILE = "mac_updates.json"
CAPTURE_INTERFACE = "eth1"

# Tabla dinámica MAC ↔ interfaz
mac_table = {}

# Cola para procesar actualizaciones del archivo
update_queue = queue.Queue()

def follow_mac_updates(file_path):
    """Lee el archivo mac_updates.json en tiempo real y actualiza la tabla MAC."""
    with open(file_path, "r") as f:
        f.seek(0, 2)  # Ir al final del archivo
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                data = json.loads(line.strip())
                update_queue.put(data)
            except json.JSONDecodeError:
                continue

def update_mac_table():
    """Procesa datos del queue y actualiza la tabla MAC en memoria."""
    while True:
        data = update_queue.get()
        if "updates" in data:
            for entry in data["updates"]:
                path = entry["Path"]
                mac = path.split("mac[address=")[-1].rstrip("]")
                values = entry["values"]
                if values:
                    info = list(values.values())[0]
                    mac_table[mac.upper()] = {
                        "interface": info.get("destination"),
                        "last_update": info.get("last-update")
                    }
        elif "deletes" in data:
            for path in data["deletes"]:
                mac = path.split("mac[address=")[-1].rstrip("]")
                mac_table.pop(mac.upper(), None)

def correlate_packet(pkt):
    """Analiza paquetes ICMPv6 NS/NA y correlaciona con tabla MAC."""
    if IPv6 in pkt and (ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt):
        src_mac = pkt.src.upper()
        src_ipv6 = pkt[IPv6].src
        iface = pkt.sniffed_on if hasattr(pkt, 'sniffed_on') else CAPTURE_INTERFACE

        entry = mac_table.get(src_mac)

        if not entry:
            print(f"[ALERTA] MAC desconocida {src_mac} desde {src_ipv6} en {iface}")
        elif entry["interface"] != iface:
            print(f"[ALERTA] Inconsistencia: {src_mac} se esperaba en {entry['interface']}, pero apareció en {iface}")
        else:
            print(f"[OK] {src_mac} → {src_ipv6} validado en {iface}")

def start_sniffing():
    sniff(
        iface=CAPTURE_INTERFACE,
        filter="icmp6 and ip6[40] == 135 or ip6[40] == 136",
        prn=correlate_packet,
        store=0
    )

# Hilos para procesamiento paralelo
threading.Thread(target=follow_mac_updates, args=(MAC_UPDATES_FILE,), daemon=True).start()
threading.Thread(target=update_mac_table, daemon=True).start()

print("[INFO] Iniciando correlación ICMPv6 ↔ tabla MAC dinámica")
start_sniffing()
