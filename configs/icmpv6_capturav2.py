import json
import time
import threading
from scapy.all import sniff, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from datetime import datetime
import os

# Ruta a archivo que gnmic va escribiendo
MAC_UPDATES_FILE = '/data/mac_updates.json'
# Archivo con tabla final actualizada
OUTPUT_FILE = '/data/mac_ipv6_bindings_dynamic.json'

bindings = {}  # Clave: MAC, Valor: dict con interface, IPs, etc.
lock = threading.Lock()

def log(msg):
    print(f"[{datetime.utcnow().isoformat()}] {msg}")

def parse_mac_updates():
    """Monitorea el archivo generado por gnmic --log y actualiza las interfaces de las MACs."""
    log("Iniciando monitoreo de tabla MAC")
    seen_offsets = 0
    while True:
        try:
            with open(MAC_UPDATES_FILE, 'r') as f:
                lines = f.readlines()
                new_lines = lines[seen_offsets:]
                seen_offsets = len(lines)

                for line in new_lines:
                    try:
                        data = json.loads(line)
                        for update in data.get("updates", []):
                            mac_path = update["Path"]
                            values = update["values"]
                            mac_info = list(values.values())[0]
                            mac = mac_path.split("mac[address=")[-1].split("]")[0].upper()
                            interface = mac_info.get("destination", "")

                            with lock:
                                if mac not in bindings:
                                    bindings[mac] = {
                                        "mac_address": mac,
                                        "interface": interface,
                                        "ipv6_link_local": None,
                                        "ipv6_global": None,
                                        "last_seen": datetime.utcnow().isoformat()
                                    }
                                else:
                                    bindings[mac]["interface"] = interface
                                    bindings[mac]["last_seen"] = datetime.utcnow().isoformat()

                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        time.sleep(1)

def process_icmpv6(packet):
    """Procesa paquetes ICMPv6 NS para extraer direcciones IPv6 y asociarlas con MACs"""
    if IPv6 in packet and ICMPv6ND_NS in packet:
        src_ip = packet[IPv6].src
        mac = None
        if ICMPv6NDOptSrcLLAddr in packet:
            mac = packet[ICMPv6NDOptSrcLLAddr].lladdr.upper()
        if mac:
            with lock:
                if mac not in bindings:
                    bindings[mac] = {
                        "mac_address": mac,
                        "interface": None,
                        "ipv6_link_local": None,
                        "ipv6_global": None,
                        "last_seen": datetime.utcnow().isoformat()
                    }
                if src_ip.startswith("fe80"):
                    bindings[mac]["ipv6_link_local"] = src_ip
                else:
                    bindings[mac]["ipv6_global"] = src_ip
                bindings[mac]["last_seen"] = datetime.utcnow().isoformat()

def start_packet_capture(interface="eth1"):
    log(f"Iniciando captura de ICMPv6 en {interface}")
    sniff(iface=interface, filter="icmp6 and ip6[40] == 135", prn=process_icmpv6, store=0)

def write_bindings_periodically():
    log(f"Escribiendo tabla a {OUTPUT_FILE} cada 5 segundos")
    while True:
        with lock:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(list(bindings.values()), f, indent=2)
        time.sleep(5)

if __name__ == "__main__":
    t1 = threading.Thread(target=parse_mac_updates)
    t2 = threading.Thread(target=start_packet_capture, kwargs={"interface": "eth1"})
    t3 = threading.Thread(target=write_bindings_periodically)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()
