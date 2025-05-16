import subprocess
import json
import signal
import re
from collections import defaultdict
from datetime import datetime, timezone
import threading

# Interfaces a monitorear
INTERFACES = ["e1-2", "e1-3", "e1-4"]
bindings = defaultdict(lambda: defaultdict(list))  # {interface: [entradas]}
seen_entries = set()
processes = []

def add_entry(interface, mac, ipv6):
    key = (interface, mac, ipv6)
    if key not in seen_entries:
        seen_entries.add(key)
        entry = {
            "mac": mac,
            "ipv6": ipv6,
            "interface": interface,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        bindings[interface].append(entry)
        print(f"[✓] {interface}: {entry}")

def flush_block(interface_data):
    for block_info in interface_data:
        interface = block_info["interface"]
        current_block = block_info["block"]
        mac = None
        ipv6_link_local = None
        ipv6_global = None
        is_valid_packet = False

        print(f"\n[DEBUG] Procesando bloque en {interface}:")
        for line in current_block:
            print(f"[DEBUG] {line}")

            if "neighbor solicitation" in line or "router solicitation" in line:
                is_valid_packet = True

            match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
            if match_mac:
                mac = match_mac.group(1).lower()
                print(f"[DEBUG] [{interface}] MAC detectada: {mac}")

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

            match_target = re.search(r'who has ([0-9a-f:]+)', line)
            if match_target:
                target_candidate = match_target.group(1)
                if target_candidate.startswith("fe80"):
                    ipv6_link_local = target_candidate
                    print(f"[DEBUG] [{interface}] IPv6 link-local (target) detectado: {ipv6_link_local}")
                else:
                    ipv6_global = target_candidate
                    print(f"[DEBUG] [{interface}] IPv6 global (target) detectado: {ipv6_global}")

        if is_valid_packet and mac:
            if ipv6_link_local:
                add_entry(interface, mac, ipv6_link_local)
            if ipv6_global:
                add_entry(interface, mac, ipv6_global)
        else:
            print(f"[DEBUG] [{interface}] Paquete descartado")

        block_info["block"] = []

def start_interface_capture(interface):
    current_block = []
    print(f"[*] Iniciando captura en interfaz: {interface}")

    tcpdump_filter = "icmp6"
    try:
        proc = subprocess.Popen(
            ["sudo", "tcpdump", "-l", "-i", interface, "-v", "-n", tcpdump_filter],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        processes.append(proc)

        print(f"[✓] tcpdump iniciado en {interface}")
        packet_count = 0

        for line in proc.stdout:
            line = line.strip()
            if "ICMP6" in line:
                packet_count += 1
                print(f"[PACKET] {interface} | {line[:80]}...")  # Mostrar parte del paquete

            if line.startswith("IP6"):
                flush_block([{"interface": interface, "block": current_block}])
                current_block = []
            current_block.append(line)

        # Vaciar último bloque
        if current_block:
            flush_block([{"interface": interface, "block": current_block}])

        print(f"[✓] Finalizada captura en {interface} | Paquetes procesados: {packet_count}")

    except Exception as e:
        print(f"[ERROR] Falló captura en {interface}: {str(e)}")

def signal_handler(sig, frame):
    print("\n[+] Captura detenida. Escribiendo archivo JSON...")
    with open("icmpv6_bindings.json", "w") as f:
        json.dump(bindings, f, indent=2)
    print("[✓] Archivo generado: icmpv6_bindings.json")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Crear hilos para cada interfaz
threads = []
for interface in INTERFACES:
    thread = threading.Thread(target=start_interface_capture, args=(interface,))
    thread.daemon = True
    thread.start()
    threads.append(thread)

print(f"[*] Capturando ICMPv6 en las interfaces: {', '.join(INTERFACES)}... Presiona Ctrl+C para detener.")

# Mantener ejecución activa
for thread in threads:
    thread.join()
