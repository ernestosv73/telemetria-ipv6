import subprocess
import re
import json
from datetime import datetime
import sys

# Función para parsear una línea de Neighbor Solicitation u otros paquetes ICMPv6
def parse_icmp6_line(line):
    # Patrón para encontrar direcciones IPv6
    ipv6_pattern = r"([0-9a-fA-F:]+)(?: > |$)"
    mac_pattern = r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})"

    ipv6_match = re.search(ipv6_pattern, line)
    if not ipv6_match:
        return None, None

    ipv6_address = ipv6_match.group(1)

    # Si es Neighbor Solicitation, la IP destino contiene "who has"
    if "who has" in line:
        who_has_pos = line.find("who has ")
        if who_has_pos != -1:
            ipv6_in_who_has = line[who_has_pos + 8:].strip().split()[0]
            ipv6_address = ipv6_in_who_has

    # Buscar MAC address en línea
    mac_match = re.search(mac_pattern, line)
    mac_address = mac_match.group(1).lower() if mac_match else None

    return ipv6_address, mac_address

# Función principal
def main(interface="e1-2", output_file="output.json"):
    command = ["sudo", "tcpdump", "-i", interface, "-n", "icmp6"]
    print(f"Ejecutando tcpdump en interfaz {interface}. Presione Ctrl+C para salir.")

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        results = {}
        current_mac = None
        current_ipv6 = None

        for line in process.stdout:
            line = line.strip()
            print(line)  # Opcional: mostrar salida en tiempo real

            # Verificar si hay mensaje relevante
            if "ICMP6, neighbor solicitation" in line or \
               "ICMP6, router solicitation" in line or \
               "ICMP6, router advertisement" in line:

                ipv6, mac = parse_icmp6_line(line)
                if ipv6 and mac:
                    current_mac = mac
                    current_ipv6 = ipv6

            elif current_mac and current_ipv6:
                # Buscar patrón de source link-address en líneas siguientes
                if "source link-address option" in line:
                    match = re.search(r"([0-9a-fA-F:]+)", line)
                    if match:
                        mac_in_opt = match.group(1).lower()
                        if mac_in_opt == current_mac:
                            timestamp = datetime.utcnow().isoformat() + "Z"
                            entry = {
                                "mac": current_mac,
                                "ipv6": current_ipv6,
                                "interface": interface,
                                "timestamp": timestamp
                            }
                            if interface not in results:
                                results[interface] = []
                            if entry not in results[interface]:
                                results[interface].append(entry)
                                print(f"Añadido: {entry}")
                current_mac = None
                current_ipv6 = None

        # Guardar resultados en JSON
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Datos guardados en {output_file}")

    except KeyboardInterrupt:
        print("\nCaptura detenida por usuario.")
        sys.exit(0)

if __name__ == "__main__":
    main(interface="e1-2")
