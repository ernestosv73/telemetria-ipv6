#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

# Iniciar capturas
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null
done

echo "[*] Procesando paquetes ICMPv6..."

declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    INTERFACE_BINDINGS["$IFACE"]="[]"

    # Mostrar contenido del paquete con formato legible
    tcpdump -nn -e -r "$FILE" 2>/dev/null | while read -r line; do

        SRC_MAC=""
        DST_IP=""
        SRC_IP=""
        FINAL_MAC=""
        FINAL_IP=""

        # Extraer MAC origen desde Ethernet header
        if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IPv6 destino en Neighbor Solicitation (who has)
        if [[ "$line" =~ who\ has\ ([0-9a-fA-F:\.\%]+) ]]; then
            DST_IP="${BASH_REMATCH[1],,}"
            FINAL_IP="$DST_IP"
        fi

        # Extraer IPv6 origen en Neighbor Advertisement
        if [[ "$line" =~ from\ ([0-9a-fA-F:\.\%]+) ]]; then
            SRC_IP="${BASH_REMATCH[1],,}"
            FINAL_IP="$SRC_IP"
        fi

        # Usar MAC si está disponible
        if [[ -n "$SRC_MAC" ]]; then
            FINAL_MAC="$SRC_MAC"
        fi

        # Registrar binding si tenemos ambos valores
        if [[ -n "$FINAL_MAC" && -n "$FINAL_IP" ]]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

            BINDING=$(jq -n \
                --arg mac "$FINAL_MAC" \
                --arg ipv6 "$FINAL_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')

            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"

            echo "[+] Binding detectado: Interface: $IFACE | MAC: $FINAL_MAC | IPv6: $FINAL_IP"
        fi
    done
done

# Generar archivo JSON final
{
    echo "{"
    FIRST=1
    for IFACE in "${INTERFACES[@]}"; do
        if [ "$FIRST" -eq 1 ]; then
            FIRST=0
        else
            echo ","
        fi
        echo "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}"
    done
    echo "}"
} > "$BINDING_FILE"

# Eliminar duplicados si jq está disponible
if command -v jq &> /dev/null; then
    jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
else
    echo "[!] jq no encontrado. No se eliminaron duplicados."
fi

# Mostrar resultado final
echo "[✓] Archivo JSON generado en: $BINDING_FILE"
cat "$BINDING_FILE"
