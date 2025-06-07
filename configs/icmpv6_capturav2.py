import subprocess
import threading
import json
import time
import os
from datetime import datetime

gnmic_cmd = [
    "gnmic",
    "--log=json",
    "-a", "srlswitch:57400",
    "-u", "admin",
    "-p", "admin",
    "--insecure",
    "subscribe",
    "--path", "/network-instance[name=lanswitch]/bridge-table/mac-table/mac[address=*]",
    "--stream-mode", "sample",
    "--sample-interval", "5s",
    "--subscription-name", "srl-mac-table"
]

mac_table = {}

def monitorear_tabla_mac():
    global mac_table
    print(f"[{datetime.now().isoformat()}] Iniciando monitoreo de tabla MAC")
    process = subprocess.Popen(gnmic_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            for update in data.get("updates", []):
                path = update.get("Path", "")
                if "mac[address=" in path:
                    mac_address = path.split("mac[address=")[-1].rstrip("]")
                    values = update.get("values", {})
                    mac_info = values.get(
                        "srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table/mac",
                        {}
                    )
                    mac_table[mac_address] = {
                        "interface": mac_info.get("destination", ""),
                        "timestamp": datetime.now().isoformat()
                    }
        except json.JSONDecodeError:
            print(f"[{datetime.now().isoformat()}] Línea no es JSON válido: {line}")
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Error procesando línea: {e}")

def guardar_tabla_periodicamente(ruta_archivo, intervalo):
    while True:
        try:
            with open(ruta_archivo, "w") as f:
                json.dump(mac_table, f, indent=2)
            print(f"[{datetime.now().isoformat()}] Escribiendo tabla a {ruta_archivo}")
        except Exception as e:
            print(f"[{datetime.now().isoformat()}] Error al guardar archivo: {e}")
        time.sleep(intervalo)

if __name__ == "__main__":
    ruta_archivo = "/data/mac_ipv6_bindings_dynamic.json"
    intervalo_guardado = 5  # segundos

    t1 = threading.Thread(target=monitorear_tabla_mac)
    t2 = threading.Thread(target=guardar_tabla_periodicamente, args=(ruta_archivo, intervalo_guardado))

    t1.start()
    t2.start()

    t1.join()
    t2.join()
