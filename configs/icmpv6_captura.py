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
    ipv6_target = None

    for line in current_block:
        # Extraer dirección origen del paquete
        match_ipv6_src = re.search(r'IP6.*?([0-9a-f:]+) >', line)
        if match_ipv6_src:
            ipv6_src = match_ipv6_src.group(1)

        # Extraer dirección solicitada en NS
        match_ipv6_target = re.search(r'who has ([0-9a-f:]+)', line)
        if match_ipv6_target:
            ipv6_target = match_ipv6_target.group(1)

        # Extraer MAC del campo "source link-address option"
        match_mac = re.search(r'source link-address option.*?: ([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1)

    if mac:
        for ip in [ipv6_src, ipv6_target]:
            if ip:
                key = (mac, ip)
                if key not in seen_entries:
                    seen_entries.add(key)
                    entry = {
                        "mac": mac,
                        "ipv6": ip,
                        "interface": INTERFACE,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    bindings[INTERFACE].append(entry)
                    print(f"[✓] Capturado: {entry}")

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
