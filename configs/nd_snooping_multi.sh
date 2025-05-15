#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal
mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

declare -A BINDINGS
for IFACE in "${INTERFACES[@]}"; do
    BINDINGS["$IFACE"]="[]"
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    # Procesar con formato más simple y confiable
    tcpdump -nn -r "$FILE" -e 'icmp6' 2>/dev/null | while read -r line; do
        SRC_MAC=""
        IPV6=""
        
        # Extraer MAC origen (primer MAC en la línea)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IPv6 basado en patrones específicos
        if [[ "$line" =~ "who has" ]]; then
            # Neighbor Solicitation
            if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        elif [[ "$line" =~ "tgt is" ]]; then
            # Neighbor Advertisement
            if [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        elif [[ "$line" =~ "router solicitation" ]]; then
            # Router Solicitation (usar dirección de origen)
            if [[ "$line" =~ ([0-9a-fA-F:]+)\. ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        fi

        # Registrar binding si tenemos ambos valores
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$IPV6" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
            
            CURRENT=$(echo "${BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            BINDINGS["$IFACE"]="$CURRENT"
            
            echo "[$IFACE] Registrado: $IPV6 -> $SRC_MAC"
        fi
    done
done

# Generar JSON final
echo "{" > "$BINDING_FILE"
FIRST=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST" -eq 0 ]; then
        echo "," >> "$BINDING_FILE"
    else
        FIRST=0
    fi
    echo -n "  \"$IFACE\": ${BINDINGS[$IFACE]}" >> "$BINDING_FILE"
done
echo -e "\n}" >> "$BINDING_FILE"

# Limpiar duplicados
jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Resultados guardados en: $BINDING_FILE"
jq . "$BINDING_FILE"
