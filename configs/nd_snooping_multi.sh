#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"

# Inicializar archivo JSON principal
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
# Procesar cada interfaz y acumular resultados en un array
declare -a ALL_BINDINGS=()

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"
    
    # Procesar paquetes para esta interfaz
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
            
            # Crear objeto JSON para este binding
            BINDING_JSON=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$INTF" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')
            
            # Agregar a array temporal (usando un archivo temporal)
            TEMP_FILE="/tmp/binding_$$.tmp"
            echo "$BINDING_JSON" >> "$TEMP_FILE"
        fi
    done
    
    # Si hay bindings para esta interfaz, agregarlos al array principal
    if [ -f "$TEMP_FILE" ]; then
        while IFS= read -r line; do
            ALL_BINDINGS+=("$line")
        done < "$TEMP_FILE"
        rm -f "$TEMP_FILE"
    fi
done

# Combinar todos los bindings en el archivo final
if [ ${#ALL_BINDINGS[@]} -gt 0 ]; then
    # Convertir array a JSON válido
    printf '%s\n' "${ALL_BINDINGS[@]}" | jq -s 'unique_by(.ipv6)' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
