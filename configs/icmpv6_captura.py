def parse_tcpdump_line(line):
    print(f"[tcpdump] {line.strip()}")  # 🪵 Log de línea cruda

    mac = None
    ipv6 = None

    timestamp = datetime.now(timezone.utc).isoformat()

    match_ipv6 = re.search(r'IP6.*? ([0-9a-f:]+) >', line)
    if match_ipv6:
        ipv6 = match_ipv6.group(1)
        print(f"  ↪ IPv6 extraída: {ipv6}")

    match_mac = re.search(r'source link-address option.*?: ([0-9a-f:]{17})', line)
    if match_mac:
        mac = match_mac.group(1)
        print(f"  ↪ MAC extraída: {mac}")

    match_unknown_opt = re.search(r'0x0000:\s+([0-9a-f]{4})\s+([0-9a-f]{4})\s+([0-9a-f]{4})', line)
    if match_unknown_opt:
        hex_mac = match_unknown_opt.groups()
        mac = ":".join([
            hex_mac[0][:2], hex_mac[0][2:],
            hex_mac[1][:2], hex_mac[1][2:],
            hex_mac[2][:2], hex_mac[2][2:]
        ])
        print(f"  ↪ MAC (NS) extraída: {mac}")

    match_who_has = re.search(r'who has ([0-9a-f:]+)', line)
    if match_who_has:
        ipv6 = match_who_has.group(1)
        print(f"  ↪ IPv6 (who has) extraída: {ipv6}")

    if mac and ipv6:
        key = (mac, ipv6)
        if key not in seen_entries:
            seen_entries.add(key)
            entry = {
                "mac": mac,
                "ipv6": ipv6,
                "interface": INTERFACE,
                "timestamp": timestamp
            }
            bindings[INTERFACE].append(entry)
            print(f"  ✅ Entrada agregada: {entry}")
