import subprocess
import re
from datetime import datetime
import json
import sys

# Función para extraer IPv6 y MAC desde cualquier línea relevante
def extract_icmp6_info(line):
    # Patrón para IPv6
    ipv6_pattern = r"([0-9a-fA-F:]+)(?=\s*[>|$])"
    # Patrón para MAC (en varios formatos comunes)
    mac_pattern = r"([0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2}:[0-9a-fA-F]{1,2})"

    # Extraer IPv6
    ipv6_match = re.search(ipv6_pattern, line)
    if not ipv6_match:
        return None, None

    ipv6 = ipv6_match.group(1)

    # Si es Neighbor Solicitation, buscar "who has"
    if "who has" in line:
        who_has_pos = line.find("who has ")
        if who_has_pos != -1:
            ipv6_in_who_has = line[who_has_pos + 8:].strip().split()[0]
            ipv6 = ipv6_in_who_has

    # Extraer MAC
    mac_match = re.search(mac_pattern, line)
    mac = mac_match.group(1).lower() if mac_match else None

    return ipv6, mac

# Función principal
def main(interface="e1-2", output_file="output.json"):
    command = ["sudo", "tcpdump", "-i", interface, "-n", "icmp6"]
    print(f"Ejecutando tcpdump en interfaz {interface}. Presione Ctrl+C para salir.")

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        results = {}
        seen_entries = set()  # Para evitar duplicados

        for line in process.stdout:
            line = line.strip()
            print(line)  # Opcional: mostrar salida en tiempo real

            if "ICMP6," in line and ("neighbor solicitation" in line or "router solicitation" in line or "router advertisement" in line):
                ipv6, mac = extract_icmp6_info(line)

                if ipv6 and mac:
                    entry_tuple = (ipv6, mac)

                    if entry_tuple not in seen_entries:
                        seen_entries.add(entry_tuple)

                        timestamp = datetime.utcnow().isoformat() + "Z"
                        entry = {
                            "mac": mac,
                            "ipv6": ipv6,
                            "interface": interface,
                            "timestamp": timestamp
                        }

                        if interface not in results:
                            results[interface] = []
                        results[interface].append(entry)
                        print(f"Añadido: {entry}")

        # Guardar resultados en JSON
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Datos guardados en {output_file}")

    except KeyboardInterrupt:
        print("\nCaptura detenida por usuario.")
        # Guardar datos antes de salir
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Datos parciales guardados en {output_file}")
        sys.exit(0)

if __name__ == "__main__":
    main(interface="e1-2")
