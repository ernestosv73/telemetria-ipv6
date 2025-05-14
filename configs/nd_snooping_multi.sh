#!/bin/bash

OUTPUT="nd_snooping.json"
INTERFACES=("e1-2" "e1-3")
TIMEOUT=30  # segundos de captura por interfaz

# Función para agregar binding al JSON
add_binding() {
    local interface=$1
    local mac=$2
    local ipv6=$3
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    exists=$(jq -r --arg intf "$interface" --arg mac "$mac" --arg ip "$ipv6" \
        'getpath([$intf, "[]", {"mac":$mac, "ipv6":$ip}])' "$OUTPUT")

    if [[ "$exists" == "null" || -z "$exists" ]]; then
        jq --arg intf "$interface" \
           --arg mac "$mac" \
           --arg ip "$ipv6" \
           --arg ts "$timestamp" \
           '.[$intf] += [{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}]' "$OUTPUT" > tmp.json && mv tmp.json "$OUTPUT"
        echo "[+] Nuevo binding: Interface: $interface | MAC: $mac | IPv6: $ipv6"
    fi
}

# Función para procesar tráfico NDP
capture_ndp() {
    local interface=$1
    echo "[*] Capturando NDP en interfaz $interface durante $TIMEOUT segundos..."

    timeout $TIMEOUT tcpdump -i $interface -nn -U -w - icmp6 |
        tshark -r - -Y "icmpv6.type == 135 or icmpv6.type == 136" -T fields \
            -e frame.interface_name \
            -e eth.src \
            -e icmpv6.opt.linkaddr \
            -e icmpv6.target \
            -e ipv6.src \
            -e icmpv6.opt.prefixinfo.prefix \
            2>/dev/null |
        while read -r _iface mac lladdr target ipaddr prefix; do

            # Usamos IP fuente (ipv6.src) o target (en caso de solicitudes)
            ipv6=${ipaddr:-$target}

            # Si hay una dirección MAC y una IPv6 válida
            if [[ -n "$mac" && -n "$ipv6" ]]; then
                add_binding "$interface" "$mac" "$ipv6"
            fi

            # También registrar la dirección link-local si está presente
            if [[ -n "$lladdr" && -n "$mac" ]]; then
                add_binding "$interface" "$mac" "$lladdr"
            fi

            # Registrar prefijo global si se incluye (por ejemplo en RA)
            if [[ -n "$prefix" && "$prefix" != "::/0" ]]; then
                echo "[*] Prefijo detectado: $prefix en interfaz $interface"
            fi
        done
}

# Iniciar captura en cada interfaz
for intf in "${INTERFACES[@]}"; do
    capture_ndp "$intf"
done
