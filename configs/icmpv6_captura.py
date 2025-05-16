import subprocess
import json
import signal
import re
from collections import defaultdict
from datetime import datetime, timezone
import threading

INTERFACES = ["e1-2", "e1-3", "e1-4"]
bindings = defaultdict(list)
seen_entries = set()
current_blocks = {interface: [] for interface in INTERFACES}
lock = threading.Lock()

def add_entry(mac, ipv6, interface):
    key = (mac, ipv6, interface)
    with lock:
        if key not in seen_entries:
            seen_entries.add(key)
            entry = {
                "mac": mac,
                "ipv6": ipv6,
                "interface": interface,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            bindings[interface].append(entry)
            print(f"[✓] [{interface}] Capturado: {entry}")

def flush_block(interface):
    global current_blocks
    mac = None
    ipv6_link_local = None
    ipv6_global = None
    is_valid_packet = False

    print(f"\n[DEBUG] [{interface}] Procesando bloque:")
    for line in current_blocks[interface]:
        print(f"[DEBUG] [{interface}] {line}")

        # Marcar paquetes válidos
        if "neighbor solicitation" in line or "router solicitation" in line:
            is_valid_packet = True

        # Extraer MAC desde "source link-address option"
        match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1).lower()
            print(f"[DEBUG] [{interface}] MAC detectada: {mac}")

        # Extraer IPv6 origen (ej: fe80::...)
        match_ipv6_src = re.search(r'([0-9a-f:]+)\s+>\s+[0-9a-f:]+', line)
        if match_ipv6_src:
            src_candidate = match_ipv6_src.group(1)
            if src_candidate != "::":
                if src_candidate.startswith("fe80"):
                    ipv6_link_local = src_candidate
                    print(f"[DEBUG] [{interface}] IPv6 link-local detectado: {ipv6_link_local}")
                else:
                    ipv6_global = src_candidate
                    print(f"[DEBUG] [{interface}] IPv6 global detectado: {ipv6_global}")

        # Extraer IPv6 objetivo en Neighbor Solicitation ("who has")
        match_target = re.search(r'who has ([0-9a-f:]+)', line)
        if match_target:
            target_candidate = match_target.group(1)
            if target_candidate.startswith("fe80"):
                ipv6_link_local = target_candidate
                print(f"[DEBUG] [{interface}] IPv6 link-local (target) detectado: {ipv6_link_local}")
            else:
                ipv6_global = target_candidate
                print(f"[DEBUG] [{interface}] IPv6 global (target) detectado: {ipv6_global}")

    # Solo si hay MAC, guardar ambas direcciones posibles
    if is_valid_packet and mac:
        if ipv6_link_local:
            add_entry(mac, ipv6_link_local, interface)
        if ipv6_global:
            add_entry(mac, ipv6_global, interface)
    else:
        print(f"[DEBUG] [{interface}] Paquete descartado: válido={is_valid_packet}, mac={mac}")

    current_blocks[interface] = []

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Escribiendo archivo JSON...")
    for interface in INTERFACES:
        flush_block(interface)
    with open("icmpv6_bindings.json", "w") as f:
        json.dump(bindings, f, indent=2)
    print("[✓] Archivo generado: icmpv6_bindings.json")
    exit(0)

def capture_interface(interface):
    print(f"[*] [{interface}] Capturando ICMPv6...")
    
    # Filtro para RS (133) y NS (135)
    tcpdump_filter = "icmp6 and (icmp6[0] == 133 or icmp6[0] == 135)"
    
    proc = subprocess.Popen(
        ["sudo", "tcpdump", "-l", "-i", interface, "-v", "-n", tcpdump_filter],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    for line in proc.stdout:
        line = line.strip()
        if line.startswith("IP6"):
            flush_block(interface)
        current_blocks[interface].append(line)

signal.signal(signal.SIGINT, signal_handler)

# Iniciar hilos de captura para cada interfaz
threads = []
for interface in INTERFACES:
    t = threading.Thread(target=capture_interface, args=(interface,))
    t.daemon = True
    t.start()
    threads.append(t)

print("[*] Captura iniciada en todas las interfaces. Presiona Ctrl+C para detener.")

# Mantener el programa principal en ejecución
try:
    while True:
        pass
except KeyboardInterrupt:
    signal_handler(None, None)
