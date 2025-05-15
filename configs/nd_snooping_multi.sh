#!/bin/bash

# Interfaces a monitorear
INTERFACES=("e1-2" "e1-3" "e1-4")
DURACION=30
TMP_DIR="/tmp/nd_snooping"
OUTPUT_JSON="/root/bindings.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$TMP_DIR"
rm -f "$TMP_DIR"/*.pcap "$OUTPUT_JSON"

echo "[*] Capturando mensajes ND (NS/NA) durante $DURACION segundos..."

# Capturar ND en paralelo para cada interfaz
for IFACE in "${INTERFACES[@]}"; do
    tcpdump -i "$IFACE" -n -w "$TMP_DIR/$IFACE.pcap" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' >/dev/null 2>&1 &
done

# Esperar captura
sleep "$DURACION"
killall tcpdump 2>/dev/null

echo "[*] Procesando paquetes ND..."

declare -A BINDINGS_JSON
for IFACE in "${INTERFACES[@]}"; do
    PCAP="$TMP_DIR/$IFACE.pcap"
    JSON_ENTRIES=()

    if [[ -f "$PCAP" ]]; then
        tcpdump -nn -r "$PCAP" -e -vvv icmp6 2>/dev/null | while read -r line; do
            # Extraer MAC de origen
            if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
                SRC_MAC="${BASH_REMATCH[1],,}"
            fi

            # Extraer IPv6 de origen del paquete
            if [[ "$line" =~ IP6[[:space:]]([0-9a-fA-F:]+)[[:space:]]?> ]]; then
                IPV6="${BASH_REMATCH[1],,}"

                # Saltar si la IP es "::" (no válida)
                if [[ "$IPV6" == "::" ]]; then
                    continue
                fi

                # Agregar al JSON
                ENTRY=$(jq -n \
                    --arg mac "$SRC_MAC" \
                    --arg ipv6 "$IPV6" \
                    --arg intf "$IFACE" \
                    --arg ts "$TIMESTAMP" \
                    '{mac: $mac, ipv6: $ipv6, interface: $intf, timestamp: $ts}')
                JSON_ENTRIES+=("$ENTRY")

                echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            fi
        done
    fi

    # Agregar entradas al array principal
    BINDINGS_JSON["$IFACE"]="[ $(IFS=,; echo "${JSON_ENTRIES[*]}") ]"
done

# Generar JSON final
{
    echo "{"
    for IFACE in "${!BINDINGS_JSON[@]}"; do
        echo "  \"$IFACE\": ${BINDINGS_JSON[$IFACE]},"
    done | sed '$s/,$//'
    echo "}"
} > "$OUTPUT_JSON"

echo "[✓] Tabla final generada en: $OUTPUT_JSON"
cat "$OUTPUT_JSON"
