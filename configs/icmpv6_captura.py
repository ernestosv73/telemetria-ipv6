import subprocess
import json
import signal
import re
from collections import defaultdict
from datetime import datetime, timezone

INTERFACE = "e1-2"
bindings = defaultdict(list)
seen_entries = set()
current_block = []

def flush_block():
    global current_block
    mac = None
    ipv6 = None

    for line in current_block:
        # Línea con dirección IPv6 origen
        match_ipv6_src = re.search(r'IP6.*?([0-9a-f:]+) >', line)
        if match_ipv6_src:
            ipv6 = match_ipv6_src.group(1)

        # Línea con dirección IPv6 "who has"
        match_ipv6_who_has = re.search(r'who has ([0-9a-f:]+)', line)
        if match_ipv6_who_has:
            ipv6 = match_ipv6_who_has.group(1)

        # Línea con opción de dirección MAC
        match_mac = re.search(r'link-address option.*?: ([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1)

        # Opción tipo 14 (usualmente en NS)
        match_unknown_opt = re.search(r'0x0000:\s+([0-9a-f]{4})\s+([0-9a-f]{4})\s+([0-9a-f]{4})', line)
        if match_unknown_opt:
            hex_mac = match_unknown_opt.groups()
            mac = ":".join([
                hex_mac[0][:2], hex_mac[0][2:],
                hex_mac[1][:2], hex_mac[1][2:],
                hex_mac[2][:2], hex_mac[2][2:]
            ])

    if mac and ipv6:
        key = (mac, ipv6)
        if key not in seen_entries:
            seen_entries.add(key)
            entry = {
                "mac": mac,
                "ipv6": ipv6,
                "interface": INTERFACE,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            bindings[INTERFACE].append(entry)
            print(f"[✓] Capturado: {entry}")

    current_block = []

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Escribiendo archivo JSON...")
    flush_block()  # Procesar el último bloque pendiente
    with open("icmpv6_bindings.json", "w") as f:
        json.dump(bindings, f, indent=2)
    print("[✓] Archivo generado: icmpv6_bindings.json")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

print(f"[*] Capturando ICMPv6 en la interfaz {INTERFACE}... Presiona Ctrl+C para detener.")

proc = subprocess.Popen(
    ["tcpdump", "-l", "-i", INTERFACE, "-v", "-n", "icmp6"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

for line in proc.stdout:
    line = line.strip()
    if line.startswith("IP6"):
        flush_block()
    current_block.append(line)
