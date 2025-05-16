import subprocess
import json
import signal
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone

INTERFACES = ["e1-2", "e1-3", "e1-4"]
bindings = defaultdict(list)
seen_entries = set()
current_blocks = {iface: [] for iface in INTERFACES}
procs = []

def add_entry(interface, mac, ipv6):
    key = (mac, ipv6)
    if key not in seen_entries:
        seen_entries.add(key)
        entry = {
            "mac": mac,
            "ipv6": ipv6,
            "interface": interface,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        bindings[interface].append(entry)
        print(f"[✓] Capturado en {interface}: {entry}")

def flush_block(interface):
    block = current_blocks[interface]
    mac = None
    ipv6_link_local = None
    ipv6_global = None
    is_valid_packet = False

    print(f"\n[DEBUG] Procesando bloque en {interface}:")
    for line in block:
        print(f"[DEBUG] {line}")

        if "neighbor solicitation" in line or "router solicitation" in line:
            is_valid_packet = True

        match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1).lower()
            print(f"[DEBUG] MAC detectada: {mac}")

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

        match_target = re.search(r'who has ([0-9a-f:]+)', line)
        if match_target:
            target_candidate = match_target.group(1)
            if target_candidate.startswith("fe80"):
                ipv6_link_local = target_candidate
                print(f"[DEBUG] IPv6 link-local (target) detectado: {ipv6_link_local}")
            else:
                ipv6_global = target_candidate
                print(f"[DEBUG] IPv6 global (target) detectado: {ipv6_global}")

    if is_valid_packet and mac:
        if ipv6_link_local:
            add_entry(interface, mac, ipv6_link_local)
        if ipv6_global:
            add_entry(interface, mac, ipv6_global)
    else:
        print(f"[DEBUG] Paquete descartado en {interface}: válido={is_valid_packet}, mac={mac}")

    current_blocks[interface] = []

def capture_interface(interface):
    print(f"[*] Capturando ICMPv6 en la interfaz {interface}...")
    tcpdump_filter = "icmp6 and (icmp6[0] == 133 or icmp6[0] == 135)"

    proc = subprocess.Popen(
        ["sudo", "tcpdump", "-l", "-i", interface, "-v", "-n", tcpdump_filter],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    procs.append(proc)

    for line in proc.stdout:
        line = line.strip()
        if line.startswith("IP6"):
            flush_block(interface)
        current_blocks[interface].append(line)

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Cerrando procesos y escribiendo JSON...")
    for iface in INTERFACES:
        flush_block(iface)
    for p in procs:
        p.terminate()
    with open("icmpv6_bindings.json", "w") as f:
        json.dump(bindings, f, indent=2)
    print("[✓] Archivo generado: icmpv6_bindings.json")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Iniciar captura en paralelo
threads = []
for iface in INTERFACES:
    t = threading.Thread(target=capture_interface, args=(iface,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
