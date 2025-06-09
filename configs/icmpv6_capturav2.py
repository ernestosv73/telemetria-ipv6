import json
import time
import threading
import datetime
from scapy.all import sniff, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, Ether

# Configuración
INTERFAZ = "eth1"
ARCHIVO_MACS = "/data/mac_updates.json"
ARCHIVO_SALIDA = "/data/mac_ipv6_bindings_dynamic.json"
MAC_UPDATE_INTERVAL = 10  # segundos

mac_lookup = {}  # MAC -> interfaz
bindings = {}    # MAC -> datos de IPv6 y timestamp

def cargar_mac_lookup():
    global mac_lookup
    try:
        with open(ARCHIVO_MACS, 'r') as f:
            data = f.read().splitlines()
            new_lookup = {}
            for line in data:
                if '"mac-table"' not in line:
                    continue
                try:
                    entry = json.loads(line)
                    mac_address = entry['updates'][0]['values']['mac-address']
                    interface = entry['updates'][0]['values']['interface']
                    new_lookup[mac_address.lower()] = interface
                except (KeyError, IndexError, json.JSONDecodeError):
                    continue
            mac_lookup = new_lookup
            print(f"[INFO] Tabla MAC actualizada. Entradas: {len(mac_lookup)}")
    except Exception as e:
        print(f"[ERROR] Al actualizar tabla MAC: {e}")

def refrescar_tabla_mac():
    while True:
        cargar_mac_lookup()
        time.sleep(MAC_UPDATE_INTERVAL)

def procesar_paquete(pkt):
    if not pkt.haslayer(Ether):
        return
    mac_origen = pkt[Ether].src.lower()

    if not pkt.haslayer(IPv6):
        return

    if not (pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA)):
        return

    print(f"[DEBUG] Paquete ICMPv6 recibido de MAC: {mac_origen}, IP: {pkt[IPv6].src}")

    if mac_origen not in mac_lookup:
        print(f"[DEBUG] MAC {mac_origen} NO encontrada en mac_lookup")
        print(f"[DEBUG] MACs disponibles: {list(mac_lookup.keys())}")
        return

    print(f"[DEBUG] MAC {mac_origen} encontrada. Procesando binding...")
    ip_target = pkt[ICMPv6ND_NS].tgt if pkt.haslayer(ICMPv6ND_NS) else pkt[ICMPv6ND_NA].tgt

    es_link_local = ip_target.startswith("fe80")
    print(f"[DEBUG] ip_target extraída: {ip_target}")
    print(f"[DEBUG] ¿Es link-local? {es_link_local}")

    if mac_origen not in bindings:
        bindings[mac_origen] = {
            "mac": mac_origen,
            "interface": mac_lookup[mac_origen],
            "ipv6_link_local": None,
            "ipv6_global": None,
            "timestamp": None
        }

    campo = "ipv6_link_local" if es_link_local else "ipv6_global"
    bindings[mac_origen][campo] = ip_target
    bindings[mac_origen]["timestamp"] = datetime.datetime.utcnow().isoformat()
    print(f"[DEBUG] Binding actualizado para {mac_origen}: {bindings[mac_origen]}")

def guardar_resultado():
    try:
        with open(ARCHIVO_SALIDA, 'w') as f:
            json.dump(list(bindings.values()), f, indent=2)
        print(f"[*] Archivo {ARCHIVO_SALIDA} guardado con {len(bindings)} bindings.")
    except Exception as e:
        print(f"[ERROR] Al guardar archivo de bindings: {e}")

# Main
if __name__ == "__main__":
    print("[*] Iniciando recarga dinámica de tabla MAC...")
    threading.Thread(target=refrescar_tabla_mac, daemon=True).start()

    print(f"[*] Iniciando captura en {INTERFAZ} (Ctrl+C para detener)...")
    try:
        sniff(iface=INTERFAZ, prn=procesar_paquete, store=0)
    except KeyboardInterrupt:
        print("[*] Captura detenida. Guardando archivo final...")
        guardar_resultado()
