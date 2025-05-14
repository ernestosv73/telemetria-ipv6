#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal y archivo de salida
mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar que todos los procesos terminen
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue
    
    INTERFACE_BINDINGS["$IFACE"]="[]"
    
    # Procesar cada paquete capturado
    while read -r line; do
        SRC_MAC=""
        IPV6=""
        TYPE=""

        # Extraer MAC origen (formato simplificado)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Determinar tipo de mensaje y extraer IPv6
        if [[ "$line" =~ "who has" ]]; then
            TYPE="NS"
            if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        elif [[ "$line" =~ "tgt is" ]]; then
            TYPE="NA"
            if [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
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
            
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
            
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
        fi

    done < <(tcpdump -nn -r "$FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)
done

# Generar el archivo JSON final
echo "{" > "$BINDING_FILE"
FIRST=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST" -eq 1 ]; then
        FIRST=0
    else
        echo "," >> "$BINDING_FILE"
    fi
    
    echo -n "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}" >> "$BINDING_FILE"
done
echo -e "\n}" >> "$BINDING_FILE"

# Eliminar duplicados
jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
