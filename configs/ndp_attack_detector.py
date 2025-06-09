#!/usr/bin/env python3

import json
import time
import hashlib
import requests
from datetime import datetime
from collections import defaultdict

# Configuración
BINDINGS_FILE = "/data/mac_ipv6_bindings_dynamic.json"
ES_URL = "http://172.20.20.9:9200"
ALERT_INDEX_PREFIX = "ndp-alerts"
INTERVALO_SEGUNDOS = 5
FLOOD_UMBRAL = 10  # número de mensajes por intervalo por MAC/IP

# Estado
historial_ipv6 = defaultdict(set)
contador_flood = defaultdict(int)

def enviar_alerta(tipo, mac, detalle):
    alerta = {
        "timestamp": datetime.utcnow().isoformat(),
        "tipo": tipo,
        "mac": mac,
        "detalle": detalle
    }

    fecha = datetime.utcnow().strftime("%Y.%m.%d")
    index = f"{ALERT_INDEX_PREFIX}-{fecha}"
    url = f"{ES_URL}/{index}/_doc"
    headers = {"Content-Type": "application/json"}
    resp = requests.post(url, headers=headers, json=alerta)

    if resp.status_code == 201:
        print(f"[ALERTA] {tipo} detectado para {mac}")
    else:
        print(f"[!] Error al enviar alerta: {resp.status_code} {resp.text}")

def detectar_ataques(bindings):
    for entry in bindings:
        mac = entry.get("mac")
        ip_ll = entry.get("ipv6_link_local")
        ip_gl = entry.get("ipv6_global")

        # --- Detectar Spoofing ---
        nuevas_ips = set()
        if ip_ll: nuevas_ips.add(ip_ll)
        if ip_gl: nuevas_ips.add(ip_gl)

        previas = historial_ipv6[mac]
        nuevas_desconocidas = nuevas_ips - previas

        if nuevas_desconocidas:
            historial_ipv6[mac].update(nuevas_ips)
            if previas:
                enviar_alerta("IPv6 Spoofing", mac, {
                    "nuevas_ips": list(nuevas_desconocidas),
                    "anteriores": list(previas)
                })

        # --- Detectar Flooding ---
        for ip in nuevas_ips:
            clave = f"{mac}-{ip}"
            contador_flood[clave] += 1
            if contador_flood[clave] > FLOOD_UMBRAL:
                enviar_alerta("ICMPv6 Flooding", mac, {
                    "ip": ip,
                    "mensajes_en_intervalo": contador_flood[clave]
                })

def main():
    print(f"[*] Monitoreando ataques cada {INTERVALO_SEGUNDOS}s...")
    while True:
        try:
            with open(BINDINGS_FILE, "r") as f:
                bindings = json.load(f)
                detectar_ataques(bindings)
        except Exception as e:
            print(f"[!] Error leyendo bindings: {e}")

        # Reiniciar contadores de flooding cada intervalo
        contador_flood.clear()
        time.sleep(INTERVALO_SEGUNDOS)

if __name__ == "__main__":
    main()
