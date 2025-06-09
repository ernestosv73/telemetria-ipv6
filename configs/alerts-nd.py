#!/usr/bin/env python3

from scapy.all import sniff, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from collections import defaultdict
from datetime import datetime
import json
import requests
import time

# === Configuración ===
INTERFACE = "eth1"
BINDINGS_FILE = "/data/mac_ipv6_bindings_dynamic.json"
ES_URL = "http://172.20.20.9:9200"
THRESHOLD_PER_IP = 10  # NS/NA por segundo por IP
INDEX_NAME = f"ndp-alerts-{datetime.utcnow().strftime('%Y.%m.%d')}"
BULK_URL = f"{ES_URL}/{INDEX_NAME}/_bulk"

# === Cargar tabla de bindings ===
with open(BINDINGS_FILE) as f:
    bindings_list = json.load(f)

bindings = {}
for entry in bindings_list:
    mac = entry["mac"].lower()
    bindings[mac] = {
        "ipv6_link_local": entry.get("ipv6_link_local"),
        "ipv6_global": entry.get("ipv6_global")
    }

# === Contadores para flooding ===
msg_counter = defaultdict(int)
last_check = time.time()

# === Buffer para alertas ===
alerts = []

# === Función para enviar alertas a Elasticsearch ===
def flush_alerts():
    if not alerts:
        return

    bulk_data = ""
    for alert in alerts:
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(alert) + "\n"

    try:
        response = requests.post(BULK_URL, headers={"Content-Type": "application/json"}, data=bulk_data)
        print(f"[+] {len(alerts)} alertas enviadas a Elasticsearch. Código HTTP: {response.status_code}")
    except Exception as e:
        print(f"[!] Error al enviar a Elasticsearch: {e}")

    alerts.clear()

# === Procesar paquetes ICMPv6 ===
def process_packet(pkt):
    global last_check

    if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]
    ipv6 = pkt[IPv6]
    src_mac = eth.src.lower()
    src_ip = ipv6.src
    ts = datetime.utcnow().isoformat() + "Z"

    if pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
        msg_type = "NS" if pkt.haslayer(ICMPv6ND_NS) else "NA"

        # 1. Validación contra tabla de bindings
        if src_mac not in bindings or (src_ip != bindings[src_mac].get("ipv6_link_local") and src_ip != bindings[src_mac].get("ipv6_global")):
            alerts.append({
                "timestamp": ts,
                "alert_type": "spoofing",
                "message_type": msg_type,
                "source_mac": src_mac,
                "source_ip": src_ip,
                "reason": "No match in MAC–IPv6 bindings"
            })

        # 2. Contador por IP para flooding
        msg_counter[src_ip] += 1

        # Chequear umbral cada segundo
        now = time.time()
        if now - last_check >= 1:
            for ip, count in msg_counter.items():
                if count > THRESHOLD_PER_IP:
                    alerts.append({
                        "timestamp": ts,
                        "alert_type": "flooding",
                        "source_ip": ip,
                        "message_count": count,
                        "reason": "Exceeds threshold for ICMPv6 NS/NA"
                    })
            msg_counter.clear()
            last_check = now

        # Enviar alertas en lotes cada vez que haya 5 o más
        if len(alerts) >= 5:
            flush_alerts()

# === Main ===
print(f"[*] Escuchando tráfico ICMPv6 ND en '{INTERFACE}'...")
try:
    sniff(iface=INTERFACE, filter="icmp6", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\n[*] Interrumpido. Enviando alertas restantes...")
    flush_alerts()
