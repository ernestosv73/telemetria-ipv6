def flush_block(interface):
    block = current_blocks[interface]
    mac = None
    ipv6s = []
    is_valid_packet = False
    mac_detected = False

    print(f"\n[DEBUG] Procesando bloque en {interface}:")
    for line in block:
        print(f"[DEBUG] {line}")

        if "neighbor solicitation" in line or "router solicitation" in line:
            is_valid_packet = True

        match_mac = re.search(r'source link-address option.*?:\s+([0-9a-f:]{17})', line)
        if match_mac:
            mac = match_mac.group(1).lower()
            mac_detected = True
            print(f"[DEBUG] MAC detectada: {mac}")

        match_ipv6_src = re.search(r'([0-9a-f:]+)\s+>\s+[0-9a-f:]+', line)
        if match_ipv6_src:
            src_candidate = match_ipv6_src.group(1)
            if src_candidate != "::":
                ipv6s.append(src_candidate)
                print(f"[DEBUG] IPv6 detectada (src): {src_candidate}")

        match_target = re.search(r'who has ([0-9a-f:]+)', line)
        if match_target:
            target_candidate = match_target.group(1)
            ipv6s.append(target_candidate)
            print(f"[DEBUG] IPv6 detectada (target): {target_candidate}")

    if is_valid_packet and mac_detected and mac:
        for ip in ipv6s:
            add_entry(interface, mac, ip)
    else:
        print(f"[DEBUG] Paquete descartado en {interface}: válido={is_valid_packet}, mac_detected={mac_detected}, mac={mac}")

    current_blocks[interface] = []
