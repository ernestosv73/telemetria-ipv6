#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"

# Inicializar archivo JSON
echo '{"bindings": []}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
declare -A LL_BINDINGS  # Para bindings link-local
declare -A GUA_BINDINGS # Para bindings global unicast

process_packet() {
    local line="$1"
    local IFACE="$2"
    
    local SRC_MAC=""
    local IPV6=""
    local TYPE=""
    
    # Extraer MAC origen
    if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
        SRC_MAC="${BASH_REMATCH[1],,}"
    fi

    # Extraer IPv6 y determinar tipo
    if [[ "$line" =~ (who has|tgt is)\ ([0-9a-f:]+) ]]; then
        IPV6="${BASH_REMATCH[2],,}"
        if [[ "$IPV6" =~ ^fe80:: ]]; then
            TYPE="link-local"
        elif [[ "$IPV6" =~ ^2001:db8: ]]; then  # Ajustar según prefijos usados
            TYPE="global"
        fi
    fi

    if [[ -n "$SRC_MAC" && -n "$IPV6" && -n "$TYPE" ]]; then
        local KEY="${SRC_MAC}-${IFACE}"
        
        if [[ "$TYPE" == "link-local" ]]; then
            LL_BINDINGS["$KEY"]="$IPV6"
            echo "[$IFACE] Binding LL encontrado: $IPV6 -> $SRC_MAC"
        else
            GUA_BINDINGS["$KEY"]="$IPV6"
            echo "[$IFACE] Binding GUA encontrado: $IPV6 -> $SRC_MAC"
        fi
    fi
}

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    while read -r line; do
        process_packet "$line" "$IFACE"
    done < <(tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null)
done

# Generar bindings finales combinando LL y GUA
declare -a FINAL_BINDINGS=()

for KEY in "${!LL_BINDINGS[@]}"; do
    MAC_IFACE=(${KEY//-/ })
    MAC="${MAC_IFACE[0]}"
    IFACE="${MAC_IFACE[1]}"
    LL_IP="${LL_BINDINGS[$KEY]}"
    GUA_IP="${GUA_BINDINGS[$KEY]}"

    BINDING_JSON=$(jq -n \
        --arg mac "$MAC" \
        --arg ll_ip "$LL_IP" \
        --arg gua_ip "$GUA_IP" \
        --arg intf "$IFACE" \
        --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        '{mac: $mac, ipv6_link_local: $ll_ip, ipv6_global: $gua_ip, interface: $intf, timestamp: $ts}')
    
    FINAL_BINDINGS+=("$BINDING_JSON")
done

# Guardar bindings finales
if [ ${#FINAL_BINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${FINAL_BINDINGS[@]}" | jq -s '{"bindings": .}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
