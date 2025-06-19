#!/usr/bin/env python3

import json
import time
import hashlib
import requests
from datetime import datetime
from pathlib import Path

# Configuración
INPUT_FILE = "/data/acl_statistics.json"
OUTPUT_FILE = "/data/acl_matched_packets_summary.json"
ES_URL = "http://172.20.20.9:9200"
INTERVALO_SEGUNDOS = 30  # Intervalo entre ejecuciones
hashes_enviados = set()

# Función para generar hash único por entrada
def hash_entrada(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

# Procesar el archivo crudo de estadísticas ACL
def procesar_estadisticas():
    nuevos = []
    if not Path(INPUT_FILE).exists():
        print(f"[!] Archivo {INPUT_FILE} no encontrado.")
        return []

    with open(INPUT_FILE, "r") as infile:
        for line in infile:
            try:
                data = json.loads(line)
                if "updates" in data:
                    device = data.get("source", "desconocido")
                    timestamp = data.get("time")

                    for update in data["updates"]:
                        path = update.get("Path", "")
                        if "interface-id=" in path:
                            interface = path.split("interface-id=")[1].split("]")[0]
                            matched_packets_str = update["values"]["srl_nokia-acl:acl/interface/input/acl-filter/entry/statistics"]["matched-packets"]
                            matched_packets = int(matched_packets_str)

                            entry = {
                                "timestamp": timestamp,
                                "device": device,
                                "interface": interface,
                                "matched_packets": matched_packets
                            }

                            h = hash_entrada(entry)
                            if h not in hashes_enviados:
                                hashes_enviados.add(h)
                                nuevos.append(entry)

            except json.JSONDecodeError:
                continue  # Ignorar líneas no válidas como {"sync-response":true}
    return nuevos

# Guardar en archivo de resumen
def guardar_resultado(entries):
    with open(OUTPUT_FILE, "w") as outfile:
        json.dump(entries, outfile, indent=2)
    print(f"[✔] Archivo actualizado: {OUTPUT_FILE} con {len(entries)} entradas.")

# Enviar a Elasticsearch
def enviar_bulk_elasticsearch(entries):
    if not entries:
        print("[=] Sin entradas nuevas para enviar a Elasticsearch.")
        return
    fecha = datetime.utcnow().strftime("%Y.%m.%d")
    index_name = f"acl-stats-{fecha}"
    bulk_url = f"{ES_URL}/{index_name}/_bulk"

    bulk_data = ""
    for entry in entries:
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(entry) + "\n"

    headers = {"Content-Type": "application/json"}
    response = requests.post(bulk_url, headers=headers, data=bulk_data)

    if response.status_code == 200:
        print(f"[+] {len(entries)} entradas enviadas a Elasticsearch ({index_name})")
    else:
        print(f"[!] Error al enviar: {response.status_code}")
        print(response.text)

# Bucle principal
def main():
    print(f"[*] Iniciando monitoreo ACL + Elasticsearch cada {INTERVALO_SEGUNDOS}s...")
    while True:
        nuevos = procesar_estadisticas()
        if nuevos:
            guardar_resultado(nuevos)
            enviar_bulk_elasticsearch(nuevos)
        else:
            print("[=] No se detectaron nuevas estadísticas ACL.")

        time.sleep(INTERVALO_SEGUNDOS)

if __name__ == "__main__":
    main()
