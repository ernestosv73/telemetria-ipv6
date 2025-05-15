#!/bin/bash

OUTPUT="nd_snooping.json"
INTERFACES=("e1-2" "e1-3")
CAPTURE_DURATION=30
PERSISTENT=false  # Cambiar a true para ejecutar en bucle
LOGFILE="/tmp/nd_snooping.log"

# Inicializa archivo JSON si no existe
initialize_json() {
    echo '{}' > "$OUTPUT"
    for intf in "${INTERFACES[@]}"; do
        jq --arg intf "$intf" 'setpath([$intf]; [])' "$OUTPUT" > tmp.json && mv tmp.json "$OUTPUT"
    done
}

# Agrega binding al JSON solo si no existe
add_binding() {
    local interface=$1
    local mac=$2
    local ipv6=$3
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Validación básica
    if [[ ! "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        echo "[!] MAC inválida: $mac" >> "$LOGFILE"
        return
    fi

    if [[ ! "$ipv6" =~ ^([0-9a-fA-F:/]+)$ ]]; then
        echo "[!] IPv6 inválida: $ipv6" >> "$LOGFILE"
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

# Función para capturar tráfico en una interfaz
capture_interface() {
    local interface=$1
    while true; do
        echo "[*] Capturando NDP en interfaz $interface durante $CAPTURE_DURATION segundos..." >> "$LOGFILE"

        timeout "$CAPTURE_DURATION" tcpdump -i "$interface" -nn -U -w - icmp6 2>/dev/null |
            tshark -r - -Y "icmpv6.type == 135 or icmpv6.type == 136" -T fields \
                -e eth.src \
                -e icmpv6.opt.linkaddr \
                -e ipv6.src \
                -e icmpv6.target 2>/dev/null |
            while read -r mac lladdr ipaddr target; do

                # Usar ipaddr o target como posible dirección IPv6
                for ipv6 in "$ipaddr" "$target"; do
                    if [[ -n "$ipv6" ]]; then
                        add_binding "$interface" "$mac" "$ipv6"
                    fi
                done
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
