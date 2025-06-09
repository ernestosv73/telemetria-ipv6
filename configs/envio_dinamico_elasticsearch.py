import json
import time
import hashlib
import requests
from datetime import datetime

JSON_FILE = "/data/mac_ipv6_bindings_dynamic.json"
ES_URL = "http://172.20.20.9:9200"
INTERVALO_SEGUNDOS = 5

# Diccionario para rastrear hashes de entradas ya enviadas
hashes_enviados = {}

def hash_entrada(entry):
    """Genera un hash único por entrada para evitar duplicados."""
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()

def enviar_bulk(entries):
    """Envía una lista de entradas a Elasticsearch usando la API bulk."""
    if not entries:
        return

    fecha = datetime.utcnow().strftime("%Y.%m.%d")
    index_name = f"mac-ipv6-{fecha}"
    bulk_url = f"{ES_URL}/{index_name}/_bulk"

    bulk_data = ""
    for entry in entries:
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(entry) + "\n"

    headers = {"Content-Type": "application/json"}
    response = requests.post(bulk_url, headers=headers, data=bulk_data)
    
    if response.status_code == 200:
        print(f"[+] {len(entries)} entradas enviadas a {index_name}")
    else:
        print(f"[!] Error al enviar a Elasticsearch: {response.status_code}")
        print(response.text)

def leer_nuevos_bindings():
    nuevos = []
    try:
        with open(JSON_FILE, "r") as f:
            data = json.load(f)
            for entry in data:
                h = hash_entrada(entry)
                if h not in hashes_enviados:
                    nuevos.append(entry)
                    hashes_enviados[h] = True
    except Exception as e:
        print(f"[!] Error leyendo JSON: {e}")
    return nuevos

def main():
    print(f"[*] Monitoreando {JSON_FILE} cada {INTERVALO_SEGUNDOS}s...")
    while True:
        nuevos = leer_nuevos_bindings()
        if nuevos:
            enviar_bulk(nuevos)
        time.sleep(INTERVALO_SEGUNDOS)

if __name__ == "__main__":
    main()
