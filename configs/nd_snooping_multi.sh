#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
OUTPUT_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal
mkdir -p "$TMP_DIR"

# Inicializar archivo JSON con estructura correcta
echo '{}' > "$OUTPUT_FILE"

echo "[*] Capturando mensajes ND (NS/NA/RS/RA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

# Objeto JSON temporal para almacenar todos los bindings
declare -A BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue
    
    # Inicializar array para esta interfaz
    BINDINGS["$IFACE"]="[]"
    
    # Procesar paquetes para esta interfaz
    while read -r line; do
        SRC_MAC=""
        SRC_IP=""
        TGT_IP=""
        TGT_MAC=""
        TYPE=""
        
        # Extraer MAC origen
        if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
            SRC_MAC=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
        fi

        # Extraer IPv6 origen
        if [[ "$line" =~ (([0-9a-fA-F:]+)\.[0-9]+ > ([0-9a-fA-F:]+)\.[0-9]+) ]]; then
            SRC_IP="${BASH_REMATCH[2],,}"
        fi

        # Extraer tipo de mensaje ICMPv6
        if [[ "$line" =~ ICMP6, (.*), ]]; then
            TYPE="${BASH_REMATCH[1]}"
        fi

        # Extraer información específica según el tipo de mensaje
        case "$TYPE" in
            "Neighbor Solicitation")
                if [[ "$line" =~ target=([0-9a-fA-F:]+) ]]; then
                    TGT_IP="${BASH_REMATCH[1],,}"
                fi
                if [[ "$line" =~ target link-address: ([0-9a-fA-F:]+) ]]; then
                    TGT_MAC=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
                fi
                ;;
            "Neighbor Advertisement")
                if [[ "$line" =~ target=([0-9a-fA-F:]+) ]]; then
                    TGT_IP="${BASH_REMATCH[1],,}"
                fi
                if [[ "$line" =~ target link-address: ([0-9a-fA-F:]+) ]]; then
                    TGT_MAC=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
                fi
                ;;
            "Router Solicitation"|"Router Advertisement")
                # También procesamos estos mensajes ya que pueden contener información útil
                ;;
        esac

        # Determinar qué direcciones agregar a la tabla
        if [[ -n "$SRC_MAC" ]]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Agregar dirección link-local si está presente
            if [[ -n "$SRC_IP" && "$SRC_IP" =~ ^fe80:: ]]; then
                BINDING=$(jq -n \
                    --arg mac "$SRC_MAC" \
                    --arg ipv6 "$SRC_IP" \
                    --arg interface "$IFACE" \
                    --arg timestamp "$TIMESTAMP" \
                    '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
                
                CURRENT=$(echo "${BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
                BINDINGS["$IFACE"]="$CURRENT"
            fi
            
            # Agregar dirección objetivo si es global
            if [[ -n "$TGT_IP" && ! "$TGT_IP" =~ ^fe80:: ]]; then
                BINDING=$(jq -n \
                    --arg mac "$SRC_MAC" \
                    --arg ipv6 "$TGT_IP" \
                    --arg interface "$IFACE" \
                    --arg timestamp "$TIMESTAMP" \
                    '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
                
                CURRENT=$(echo "${BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
                BINDINGS["$IFACE"]="$CURRENT"
            fi
            
            # Agregar dirección MAC objetivo si es diferente
            if [[ -n "$TGT_MAC" && "$TGT_MAC" != "$SRC_MAC" ]]; then
                # Necesitamos la IP asociada a esta MAC (simplificación)
                BINDING=$(jq -n \
                    --arg mac "$TGT_MAC" \
                    --arg ipv6 "$TGT_IP" \
                    --arg interface "$IFACE" \
                    --arg timestamp "$TIMESTAMP" \
                    '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
                
                CURRENT=$(echo "${BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
                BINDINGS["$IFACE"]="$CURRENT"
            fi
        fi
    done < <(tcpdump -nn -v -r "$FILE" 'icmp6 and (ip6[40] >= 133 and ip6[40] <= 136)' 2>/dev/null)
done

# Combinar todos los bindings en el formato deseado
echo "{" > "$OUTPUT_FILE"
FIRST_IFACE=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST_IFACE" -eq 0 ]; then
        echo "," >> "$OUTPUT_FILE"
    else
        FIRST_IFACE=0
    fi
    
    echo -n "  \"$IFACE\": ${BINDINGS[$IFACE]}" >> "$OUTPUT_FILE"
done
echo -e "\n}" >> "$OUTPUT_FILE"

# Eliminar duplicados y ordenar
jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

echo "[✓] Tabla final en: $OUTPUT_FILE"
jq . "$OUTPUT_FILE"
