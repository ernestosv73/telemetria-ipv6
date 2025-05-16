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

def add_entry(mac, ipv6):
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

def flush_block():
    global current_block
    mac = None
    ipv6_link_local = None
    ipv6_global = None
    is_valid_packet = False

    print("\n[DEBUG] Procesando bloque:")
    for line in current_block:
        print(f"[DEBUG] {line}")

        # Marcar paquetes válidos
        if "neighbor solicitation" in line or "router solicitation" in line:
            is_valid_packet = True

        # Extraer MAC desde "source link-address option"
        match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1).lower()
            print(f"[DEBUG] MAC detectada: {mac}")

        # Extraer IPv6 origen (ej: fe80::...)
        match_ipv6_src = re.search(r'([0-9a-f:]+)\s+>\s+[0-9a-f:]+', line)
        if match_ipv6_src:
            src_candidate = match_ipv6_src.group(1)
            if src_candidate != "::":
                if src_candidate.startswith("fe80"):
                    ipv6_link_local = src_candidate
                    print(f"[DEBUG] IPv6 link-local detectado: {ipv6_link_local}")
                else:
                    ipv6_global = src_candidate
                    print(f"[DEBUG] IPv6 global detectado: {ipv6_global}")

        # Extraer IPv6 objetivo en Neighbor Solicitation ("who has")
        match_target = re.search(r'who has ([0-9a-f:]+)', line)
        if match_target:
            target_candidate = match_target.group(1)
            if target_candidate.startswith("fe80"):
                ipv6_link_local = target_candidate
                print(f"[DEBUG] IPv6 link-local (target) detectado: {ipv6_link_local}")
            else:
                ipv6_global = target_candidate
                print(f"[DEBUG] IPv6 global (target) detectado: {ipv6_global}")

    # Solo si hay MAC, guardar ambas direcciones posibles
    if is_valid_packet and mac:
        if ipv6_link_local:
            add_entry(mac, ipv6_link_local)
        if ipv6_global:
            add_entry(mac, ipv6_global)
    else:
        print(f"[DEBUG] Paquete descartado: válido={is_valid_packet}, mac={mac}")

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
    ["sudo", "tcpdump", "-l", "-i", INTERFACE, "-v", "-n", tcpdump_filter],
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
