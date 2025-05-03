#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
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
# Procesar cada interfaz individualmente y combinar al final
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"
    TEMP_BINDING="/tmp/bindings_${IFACE}.json"
    
    echo '{"bindings": []}' > "$TEMP_BINDING"

    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null | while read -r line; do
        SRC_MAC=""
        IPV6=""
        
        # Extraer MAC origen
        if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
            SRC_MAC=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
        fi

        # Extraer IPv6
        if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]] || [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
            IPV6=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$INTF] Binding encontrado: $IPV6 -> $SRC_MAC"
            
            # Usar un archivo temporal por interfaz
            TEMP_FILE="${TEMP_BINDING}.tmp"
            jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$INTF" --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
               '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
               "$TEMP_BINDING" > "$TEMP_FILE" && mv "$TEMP_FILE" "$TEMP_BINDING"
        fi
    done
    
    # Combinar los resultados de esta interfaz con el archivo principal
    jq -s '.[0].bindings + .[1].bindings | unique_by(.ipv6)' "$BINDING_FILE" "$TEMP_BINDING" > "${BINDING_FILE}.tmp" \
        && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
