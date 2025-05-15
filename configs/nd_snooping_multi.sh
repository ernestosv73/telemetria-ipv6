#!/bin/bash

OUTPUT="nd_snooping.json"
INTERFACES=("e1-2" "e1-3")
CAPTURE_DURATION=30
PERSISTENT=false
LOGFILE="/tmp/nd_snooping.log"

initialize_json() {
    echo '{}' > "$OUTPUT"
    for intf in "${INTERFACES[@]}"; do
        jq --arg intf "$intf" 'setpath([$intf]; [])' "$OUTPUT" > tmp.json && mv tmp.json "$OUTPUT"
    done
}

add_binding() {
    local interface=$1
    local mac=$2
    local ipv6=$3
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    if [[ ! "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        echo "[!] MAC inválida: $mac" >> "$LOGFILE"
        return
    fi

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

capture_interface() {
    local interface=$1
    while true; do
        echo "[*] Capturando NDP en interfaz $interface durante $CAPTURE_DURATION segundos..." >> "$LOGFILE"

        timeout "$CAPTURE_DURATION" tcpdump -i "$interface" -nn -U -w - icmp6 2>/dev/null |
            tshark -r - -T fields \
                -e frame.interface_name \
                -e eth.src \
                -e icmpv6.opt.linkaddr \
                -e ipv6.src \
                -e icmpv6.target \
                -e icmpv6.type \
                2>/dev/null |
            while read -r _iface mac lladdr ipaddr target type; do

                # Si viene MAC desde eth.src o icmpv6.opt.linkaddr
                final_mac=${lladdr:-$mac}

                # Elegir IPv6 entre ipaddr, target o ninguno
                final_ip=""
                for candidate in "$ipaddr" "$target"; do
                    if [[ -n "$candidate" && "$candidate" != "::" ]]; then
                        final_ip="$candidate"
                        break
                    fi
                done

                # Registrar solo si hay MAC e IPv6 válida
                if [[ -n "$final_mac" && -n "$final_ip" ]]; then
                    add_binding "$interface" "$final_mac" "$final_ip"
                fi
            done
        $PERSISTENT || break
        sleep 5
    done
}

# Inicializar estructura JSON
initialize_json

# Lanzar capturas en paralelo
for intf in "${INTERFACES[@]}"; do
    capture_interface "$intf" &
done

echo "[*] ND Snooping iniciado en paralelo en ${#INTERFACES[@]} interfaces."
echo "    Archivo de salida: $OUTPUT"
echo "    PERSISTENT MODE: $PERSISTENT"

wait
