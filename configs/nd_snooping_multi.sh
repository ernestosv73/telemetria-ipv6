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
declare -A BINDING_MAP  # Mapa principal para evitar duplicados

process_packet() {
    local line="$1"
    local IFACE="$2"
    
    local SRC_MAC=""
    local IPV6=""
    local PORT=$(echo "$IFACE" | grep -o -E '[0-9]+$')
    
    # Extraer MAC origen
    if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
        SRC_MAC="${BASH_REMATCH[1],,}"
    fi

    # Extraer IPv6 y determinar tipo
    if [[ "$line" =~ (who has|tgt is)\ ([0-9a-f:]+) ]]; then
        IPV6="${BASH_REMATCH[2],,}"
    fi

    if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
        local KEY="${SRC_MAC}-${IPV6}"
        
        echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC (Puerto: $PORT)"
        
        if [[ -n "${BINDING_MAP[$KEY]}" ]]; then
            # Actualizar binding existente
            CURRENT=$(echo "${BINDING_MAP[$KEY]}" | jq --arg intf "$IFACE" --arg port "$PORT" \
                '.interfaces += [{"interface": $intf, "port": $port}] | .last_seen=$now' --arg now "$(date -u +"%Y-%m-%dT%H:%M:%SZ")")
            BINDING_MAP[$KEY]="$CURRENT"
        else
            # Crear nuevo binding
            BINDING_MAP[$KEY]=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$IFACE" \
                --arg port "$PORT" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interfaces: [{interface: $intf, port: $port}], first_seen: $ts, last_seen: $ts}')
        fi
    fi
}

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    while read -r line; do
        process_packet "$line" "$IFACE"
    done < <(tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null)
done

# Separar en bindings link-local y global unicast
declare -a LL_BINDINGS=()
declare -a GUA_BINDINGS=()

for KEY in "${!BINDING_MAP[@]}"; do
    BINDING="${BINDING_MAP[$KEY]}"
    IPV6=$(echo "$BINDING" | jq -r '.ipv6')
    
    if [[ "$IPV6" =~ ^fe80:: ]]; then
        LL_BINDINGS+=("$BINDING")
    else
        GUA_BINDINGS+=("$BINDING")
    fi
done

# Combinar bindings por MAC
declare -a FINAL_BINDINGS=()

for LL_BINDING in "${LL_BINDINGS[@]}"; do
    MAC=$(echo "$LL_BINDING" | jq -r '.mac')
    LL_IP=$(echo "$LL_BINDING" | jq -r '.ipv6')
    INTERFACES=$(echo "$LL_BINDING" | jq '.interfaces')
    
    # Buscar GUA correspondiente
    GUA_IP="null"
    for GUA_BINDING in "${GUA_BINDINGS[@]}"; do
        if [[ $(echo "$GUA_BINDING" | jq -r '.mac') == "$MAC" ]]; then
            GUA_IP=$(echo "$GUA_BINDING" | jq -r '.ipv6')
            break
        fi
    done
    
    FINAL_BINDINGS+=($(jq -n \
        --argjson ll "$LL_BINDING" \
        --arg gua "$GUA_IP" \
        '{
            mac: $ll.mac,
            ipv6_link_local: $ll.ipv6,
            ipv6_global: ($gua | if . == "null" then empty else . end),
            interfaces: $ll.interfaces,
            first_seen: $ll.first_seen,
            last_seen: $ll.last_seen
        }'))
done

# Guardar bindings finales
if [ ${#FINAL_BINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${FINAL_BINDINGS[@]}" | jq -s '{"bindings": .}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
