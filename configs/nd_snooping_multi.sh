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
# Archivo temporal único para esta ejecución
TEMP_FILE="/tmp/nd_bindings_$$.json"
echo '{"bindings": []}' > "$TEMP_FILE"

process_interface() {
    local IFACE=$1
    local FILE="$TMP_DIR/$IFACE.pcap"
    
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
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            
            # Crear JSON para este binding
            BINDING_JSON=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$IFACE" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')
            
            # Agregar al archivo temporal
            jq --argjson binding "$BINDING_JSON" '.bindings += [$binding]' "$TEMP_FILE" > "${TEMP_FILE}.tmp" \
                && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
        fi
    done
}

# Procesar cada interfaz en el shell principal
for IFACE in "${INTERFACES[@]}"; do
    process_interface "$IFACE"
done

# Eliminar duplicados y guardar el resultado final
jq '.bindings | unique_by(.ipv6)' "$TEMP_FILE" > "$BINDING_FILE"

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"

# Limpiar archivo temporal
rm -f "$TEMP_FILE"
