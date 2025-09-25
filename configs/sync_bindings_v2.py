#!/usr/bin/env python3

import json
import time
import hashlib
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# === Configuración ===
JSON_FILE = "/data/mac_ipv6_bindings_dynamic.json"
ES_URL = "http://172.80.80.9:9200"
SRL_URL = "http://srlswitch/jsonrpc"
SRL_USER = "admin"
SRL_PASS = "NokiaSrl1!"
INTERVALO_SEGUNDOS = 15

# === Estado global ===
hashes_enviados = {}           # Hashes de entradas ya enviadas a ES
ultimo_acl_hash = None         # Hash de la última configuración de ACLs aplicada

# === Funciones auxiliares ===

def is_complete_entry(entry):
    """
    Verifica si una entrada tiene todos los campos necesarios.
    """
    return all([
        entry.get("mac"),
        entry.get("interface"),
        entry.get("ipv6_link_local"),
        isinstance(entry.get("ipv6_globals"), list) and len(entry.get("ipv6_globals")) > 0
    ])

def hash_entrada(entry):
    """
    Genera un hash único basado en MAC, interfaz, link-local y globales.
    """
    key_data = {
        "mac": entry["mac"],
        "interface": entry["interface"],
        "ipv6_link_local": entry["ipv6_link_local"],
        "ipv6_globals": sorted(entry["ipv6_globals"])  # ordenado para consistencia
    }
    return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

def leer_nuevos_bindings():
    """
    Lee el archivo JSON y devuelve solo entradas nuevas y válidas.
    """
    nuevos = []
    try:
        if not Path(JSON_FILE).exists():
            print(f"[!] Archivo {JSON_FILE} no existe.")
            return []

        with open(JSON_FILE, "r") as f:
            raw_content = f.read().strip()
            if not raw_content:
                print("[DEBUG] Archivo JSON vacío.")
                return []

            data = json.loads(raw_content)

        if not isinstance(data, list):
            print(f"[!] Formato inválido: se esperaba una lista, obtenido {type(data)}")
            return []

        print(f"[INFO] Cargadas {len(data)} entradas del archivo.")

        for i, entry in enumerate(data):
            print(f"[DEBUG] Procesando entrada {i}: {entry.get('mac')} en {entry.get('interface')}")

            if not is_complete_entry(entry):
                print(f"[WARN] Entrada {i} incompleta o inválida → omitida")
                continue

            h = hash_entrada(entry)
            print(f"       Hash: {h[:16]}...")

            if h not in hashes_enviados:
                nuevos.append(entry)
                hashes_enviados[h] = True
                print(f"       ✅ Nuevo binding detectado")
            else:
                print(f"       ⚠️ Ya procesado anteriormente")

    except json.JSONDecodeError as e:
        print(f"[!] Error de formato JSON: {e}")
    except Exception as e:
        print(f"[!] Error inesperado leyendo bindings: {e}")
        import traceback
        traceback.print_exc()

    return nuevos


# === Elasticsearch: Envío bulk ===
def enviar_bulk_elasticsearch(entries):
    if not entries:
        return

    fecha = datetime.utcnow().strftime("%Y.%m.%d")
    index_name = f"mac-ipv6-{fecha}"
    bulk_url = f"{ES_URL}/{index_name}/_bulk"

    bulk_data = ""
    for entry in entries:
        # Añadir timestamp para Kibana/Grafana
        entry["@timestamp"] = datetime.utcnow().isoformat()

        # Mensaje legible
        gua_list = ", ".join(entry["ipv6_globals"])
        entry["message"] = (
            f"[{entry['timestamp']}] "
            f"MAC: {entry['mac']} | "
            f"Interface: {entry['interface']} | "
            f"LL: {entry['ipv6_link_local']} | "
            f"GUA: {gua_list}"
        )

        # Formato bulk: {"index":{}}\n{doc}\n
        bulk_data += json.dumps({"index": {}}) + "\n"
        bulk_data += json.dumps(entry) + "\n"

    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(bulk_url, headers=headers, data=bulk_data, timeout=10)
        if response.status_code == 200 or response.status_code == 201:
            print(f"[+] {len(entries)} entradas enviadas a Elasticsearch ({index_name})")
        else:
            print(f"[!] Error en Elasticsearch ({response.status_code}): {response.text}")
    except requests.RequestException as e:
        print(f"[!] Fallo de conexión a Elasticsearch: {e}")


# === Nokia SR Linux: Generar y enviar ACLs ===
def build_and_send_acls(bindings):
    global ultimo_acl_hash

    # Generar hash de la configuración actual de ACLs
    acl_config_key = [
        (b["interface"], b["ipv6_link_local"], sorted(b["ipv6_globals"]))
        for b in bindings
    ]
    current_acl_hash = hashlib.sha256(
        json.dumps(sorted(acl_config_key), sort_keys=True).encode()
    ).hexdigest()

    if current_acl_hash == ultimo_acl_hash:
        print("[=] Sin cambios en bindings → ACLs no enviadas")
        return

    print(f"[*] Cambios detectados. Generando nuevas ACLs... ({len(bindings)} hosts)")

    # Agrupar por interfaz: todas las IPs permitidas (link-local + globales)
    interfaces_ipv6 = defaultdict(list)
    for entry in bindings:
        iface = entry["interface"]
        interfaces_ipv6[iface].append(entry["ipv6_link_local"])
        for global_ip in entry["ipv6_globals"]:
            interfaces_ipv6[iface].append(global_ip)

    commands = ["enter candidate"]
    entry_id_base = 10

    for iface, ipv6_addrs in interfaces_ipv6.items():
        seen_ips = set()
        current_id = entry_id_base

        for ip in ipv6_addrs:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {current_id} match ipv6 next-header icmp6 source-ip prefix {ip}/128"
            )
            commands.append(
                f"set acl acl-filter {iface} type ipv6 entry {current_id} action accept"
            )
            current_id += 1

        # Regla final: denegar resto de ICMPv6 (opcional, puedes ajustar)
        deny_id = current_id if current_id < 100 else 100
        commands.append(f"set acl acl-filter {iface} type ipv6 entry {deny_id} description DenyICMPv6All")
        commands.append(f"set acl acl-filter {iface} type ipv6 entry {deny_id} match ipv6 next-header icmp6")
        commands.append(f"set acl acl-filter {iface} type ipv6 entry {deny_id} action log true drop")

        # Aplicar ACL a interfaz
        commands.append(f"set acl interface {iface} input acl-filter {iface} type ipv6")
        commands.append(f"set acl acl-filter {iface} type ipv6 statistics-per-entry true")
        commands.append(f"set acl acl-filter {iface} type ipv6 subinterface-specific input-only")

    commands.append("commit stay")

    # Payload JSON-RPC
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cli",
        "params": {"commands": commands}
    }

    curl_command = [
        "curl", "-k", "-s", "-u", f"{SRL_USER}:{SRL_PASS}",
        "-X", "POST", SRL_URL,
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)
    ]

    print(f"[*] Enviando {len(commands)} comandos al switch...")
    try:
        result = subprocess.run(curl_command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("[✓] ACLs aplicadas correctamente")
            ultimo_acl_hash = current_acl_hash
        else:
            print(f"[!] Error al ejecutar curl: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("[!] Timeout al comunicarse con el switch")
    except Exception as e:
        print(f"[!] Error inesperado al enviar ACLs: {e}")


# === Main loop ===
def main():
    global hashes_enviados, ultimo_acl_hash

    # 🔁 Reiniciar estado al iniciar (útil para pruebas)
    print("[*] Reiniciando estado...")
    hashes_enviados = {}
    ultimo_acl_hash = None

    print(f"[*] Iniciando monitoreo cada {INTERVALO_SEGUNDOS}s...")
    print(f"    - Archivo: {JSON_FILE}")
    print(f"    - Destino ES: {ES_URL}")
    print(f"    - Switch: {SRL_URL}")

    while True:
        nuevos = leer_nuevos_bindings()

        if nuevos:
            print(f"[+] Nuevos bindings detectados: {len(nuevos)}")
            enviar_bulk_elasticsearch(nuevos)
            build_and_send_acls(nuevos)
        else:
            print("[=] Sin nuevos bindings válidos. No se envió nada.")

        time.sleep(INTERVALO_SEGUNDOS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Script detenido por usuario.")
    except Exception as e:
        print(f"[!] Error crítico: {e}")
        import traceback
        traceback.print_exc()
