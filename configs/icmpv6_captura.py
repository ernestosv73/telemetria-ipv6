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
    ipv6_src = None
    is_valid_packet = False

    print("\n[DEBUG] Procesando bloque:")
    for line in current_block:
        print(f"[DEBUG] {line}")

        if "neighbor solicitation" in line or "router solicitation" in line:
            is_valid_packet = True

        match_ipv6_src = re.search(r'([0-9a-f:]+)\s+>\s+[0-9a-f:]+', line)
        if match_ipv6_src:
            src_candidate = match_ipv6_src.group(1)
            if src_candidate != "::":
                ipv6_src = src_candidate
                print(f"[DEBUG] IPv6 origen detectado: {ipv6_src}")


        match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1)
            print(f"[DEBUG] MAC detectada: {mac}")

    if is_valid_packet and mac and ipv6_src:
        key = (mac, ipv6_src)
        if key not in seen_entries:
            seen_entries.add(key)
            entry = {
                "mac": mac,
                "ipv6": ipv6_src,
                "interface": INTERFACE,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            bindings[INTERFACE].append(entry)
            print(f"[✓] Capturado: {entry}")
    else:
        print(f"[DEBUG] Paquete descartado: válido={is_valid_packet}, mac={mac}, ipv6={ipv6_src}")

    current_block = []

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Escribiendo archivo JSON...")
    flush_block()
    with open("icmpv6_bindings.json", "w") as f:
        json.dump(bindings, f, indent=2)
    print("[✓] Archivo generado: icmpv6_bindings.json")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

print(f"[*] Capturando ICMPv6 en la interfaz {INTERFACE}... Presiona Ctrl+C para detener.")

# Filtro para RS (133) y NS (135)
tcpdump_filter = "icmp6 and (icmp6[0] == 133 or icmp6[0] == 135)"

proc = subprocess.Popen(
    ["tcpdump", "-l", "-i", INTERFACE, "-v", "-n", tcpdump_filter],
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
