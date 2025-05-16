import subprocess
import re
import json
from datetime import datetime, timezone
import signal
import sys
from collections import defaultdict

# Configuración
interface = "e1-2"
output_file = "icmpv6_bindings.json"
bindings = defaultdict(list)
ipv6_seen = set()
mac = None  # Última MAC detectada

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Escribiendo archivo JSON...\n")
    with open(output_file, "w") as f:
        json.dump(bindings, f, indent=2)
    print(f"[✓] Archivo generado: {output_file}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Ejecutar tcpdump
print(f"[*] Capturando ICMPv6 en la interfaz {interface}... Presiona Ctrl+C para detener.\n")

tcpdump_cmd = [
    "tcpdump",
    "-i", interface,
    "-vvv",
    "-l",
    "icmp6"
]

process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

for line in process.stdout:
    line = line.strip()
    if not line:
        continue

    print(f"[DEBUG] {line}")

    timestamp = datetime.now(timezone.utc).isoformat()

    # Capturar MAC desde la opción "source link-address"
    match_mac = re.search(r'source link-address option.*?: ([0-9a-f:]{17})', line)
    if match_mac:
        mac = match_mac.group(1).lower()
        print(f"[DEBUG] MAC detectada: {mac}")

    # Capturar dirección IPv6 origen (link-local o global)
    match_ipv6_src = re.search(r'^.* IP6 ([0-9a-f:]+) > ', line)
    if match_ipv6_src:
        ipv6 = match_ipv6_src.group(1).lower()
        if (ipv6.startswith("fe80::") or ipv6.startswith("2001:db8:")) and mac:
            key = (mac, ipv6)
            if key not in ipv6_seen:
                entry = {
                    "mac": mac,
                    "ipv6": ipv6,
                    "interface": interface,
                    "timestamp": timestamp
                }
                bindings[interface].append(entry)
                ipv6_seen.add(key)
                print(f"[✓] Capturado: {entry}")

    # Capturar dirección IPv6 objetivo de NS ("who has ...")
    match_ns = re.search(r'who has ([0-9a-f:]+)', line)
    if match_ns:
        ipv6_target = match_ns.group(1).lower()
        if ipv6_target.startswith("2001:db8:") and mac:
            key = (mac, ipv6_target)
            if key not in ipv6_seen:
                entry = {
                    "mac": mac,
                    "ipv6": ipv6_target,
                    "interface": interface,
                    "timestamp": timestamp
                }
                bindings[interface].append(entry)
                ipv6_seen.add(key)
                print(f"[✓] Capturado: {entry}")
