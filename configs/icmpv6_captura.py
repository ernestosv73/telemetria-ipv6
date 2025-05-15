import subprocess
import re
import json
from datetime import datetime, timezone

INTERFACE = "e1-2"
OUTPUT_FILE = "icmpv6_bindings.json"
bindings = {INTERFACE: []}
seen_entries = set()

def parse_tcpdump_line(line):
    mac = None
    ipv6 = None

    # Timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    # IPv6 address extraction
    match_ipv6 = re.search(r'IP6.*? ([0-9a-f:]+) >', line)
    if match_ipv6:
        ipv6 = match_ipv6.group(1)

    # MAC address from source link-layer option
    match_mac = re.search(r'source link-address option.*?: ([0-9a-f:]{17})', line)
    if match_mac:
        mac = match_mac.group(1)

    # For NS, MAC is sometimes in a follow-up line
    match_unknown_opt = re.search(r'0x0000:\s+([0-9a-f]{4})\s+([0-9a-f]{4})\s+([0-9a-f]{4})', line)
    if match_unknown_opt:
        hex_mac = match_unknown_opt.groups()
        mac = ":".join([
            hex_mac[0][:2], hex_mac[0][2:],
            hex_mac[1][:2], hex_mac[1][2:],
            hex_mac[2][:2], hex_mac[2][2:]
        ])

    # Additional IPv6 from "who has" field
    match_who_has = re.search(r'who has ([0-9a-f:]+)', line)
    if match_who_has:
        ipv6 = match_who_has.group(1)

    if mac and ipv6:
        key = (mac, ipv6)
        if key not in seen_entries:
            seen_entries.add(key)
            bindings[INTERFACE].append({
                "mac": mac,
                "ipv6": ipv6,
                "interface": INTERFACE,
                "timestamp": timestamp
            })

def main():
    print(f"[*] Capturando ICMPv6 en la interfaz {INTERFACE}... Presiona Ctrl+C para detener.")
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", INTERFACE, "-v", "-n", "icmp6"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in proc.stdout:
            parse_tcpdump_line(line)

    except KeyboardInterrupt:
        print("\n[+] Captura detenida. Escribiendo archivo JSON...")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(bindings, f, indent=2)

    print(f"[✓] Archivo generado: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
