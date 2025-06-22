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
INTERVALO_SEGUNDOS = 30
TIEMPO_ESPERA_INICIAL = 60

hashes_enviados = set()
descripcion_acl = {}

# Esperar a que aparezca el archivo
def esperar_archivo_inicial():
    print(f"[*] Esperando a que exista {INPUT_FILE} ...")
    for _ in range(TIEMPO_ESPERA_INICIAL):
        if Path(INPUT_FILE).exists() and Path(INPUT_FILE).stat().st_size > 0:
            print(f"[✔] Archivo detectado.")
            return
        time.sleep(1)
    print(f"[✖] Tiempo de espera agotado.")
    exit(1)

# Generar hash único
def hash_entrada(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

# Extraer sequence-id desde el path
def extraer_sequence_id(path):
    try:
        return path.split("sequence-id=")[1].split("]")[0]
    except IndexError:
        return "unknown"

# Procesar estadísticas ACL y descripciones
def procesar_estadisticas():
    nuevos = []
    try:
        with open(INPUT_FILE, "r") as infile:
            for line in infile:
                try:
                    data = json.loads(line)
                    if "updates" not in data:
                        continue

                    timestamp = data.get("time")
                    device = data.get("source", "desconocido")

                    for update in data["updates"]:
                        path = update.get("Path", "")

                        # Descripciones de ACL
                        if "/acl-filter" in path and "/entry" in path and "/description" not in path and "statistics" not in path:
                            seq_id = extraer_sequence_id(path)
                            desc = update["values"]["srl_nokia-acl:acl/acl-filter/entry"].get("description", "")
                            descripcion_acl[seq_id] = desc

                        # Estadísticas ACL
                        if "interface-id=" in path and "statistics" in path:
                            interface = path.split("interface-id=")[1].split("]")[0]
                            seq_id = extraer_sequence_id(path)
                            matched_packets = int(
                                update["values"]["srl_nokia-acl:acl/interface/input/acl-filter/entry/statistics"]["matched-packets"]
                            )

                            if matched_packets > 0:
                                entry = {
                                    "timestamp": timestamp,
                                    "device": device,
                                    "interface": interface,
                                    "sequence_id": seq_id,
                                    "matched_packets": matched_packets,
                                    "description": descripcion_acl.get(seq_id, "sin descripción")
                                }

                                h = hash_entrada(entry)
                                if h not in hashes_enviados:
                                    hashes_enviados.add(h)
                                    nuevos.append(entry)
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"[!] Archivo {INPUT_FILE} no encontrado.")
    return nuevos

# Guardar archivo JSON
def guardar_resultado(entries):
    with open(OUTPUT_FILE, "w") as f:
        json.dump(entries, f, indent=2)
    print(f"[✔] {OUTPUT_FILE} actualizado con {len(entries)} entradas.")

# Enviar a Elasticsearch
def enviar_bulk_elasticsearch(entries):
    if not entries:
        print("[=] Sin entradas nuevas para enviar a Elasticsearch.")
        return
    index_name = f"acl-stats-{datetime.utcnow().strftime('%Y.%m.%d')}"
    bulk_url = f"{ES_URL}/{index_name}/_bulk"

    bulk_data = ""
    for entry in entries:
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(entry) + "\n"

    response = requests.post(bulk_url, headers={"Content-Type": "application/json"}, data=bulk_data)

    if response.status_code == 200:
        print(f"[+] {len(entries)} entradas enviadas a Elasticsearch ({index_name})")
    else:
        print(f"[!] Error al enviar: {response.status_code}")
        print(response.text)

# Loop principal
def main():
    esperar_archivo_inicial()
    print(f"[*] Iniciando monitoreo ACL + Elasticsearch cada {INTERVALO_SEGUNDOS}s...")
    while True:
        nuevos = procesar_estadisticas()
        if nuevos:
            guardar_resultado(nuevos)
            enviar_bulk_elasticsearch(nuevos)
        else:
            print("[=] No se detectaron nuevas estadísticas ACL con matched-packets > 0.")
        time.sleep(INTERVALO_SEGUNDOS)

if __name__ == "__main__":
    main()
