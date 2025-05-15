#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

# Iniciar capturas paralelas
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$PCAP_FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar finalización
for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null
done

echo "[*] Procesando paquetes ND..."

declare -A INTERFACE_BINDINGS
declare -A global_seen

# Inicializar interfaces vacías
for IFACE in "${INTERFACES[@]}"; do
    INTERFACE_BINDINGS["$IFACE"]="[]"
done

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$PCAP_FILE" ] || continue

    echo "[+] Procesando paquetes en interfaz $IFACE..."

    # Extraer líneas relevantes con tcpdump
    tcpdump -nn -e -r "$PCAP_FILE" 2>/dev/null | while read -r line; do
        SRC_MAC=""
        FINAL_IP=""

        # Extraer MAC desde Ethernet header
        if [[ "$line" =~ ([0-9a-fA-F:]{17}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Buscar patrones de Neighbor Solicitation: "who has <IPv6>"
        if [[ "$line" =~ who[[:space:]]+has[[:space:]]+([0-9a-fA-F:\.\%]+) ]]; then
            FINAL_IP="${BASH_REMATCH[1],,}"
        elif [[ "$line" =~ from[[:space:]]+([0-9a-fA-F:\.\%]+) ]]; then
            FINAL_IP="${BASH_REMATCH[1],,}"
        fi

        # Registrar binding si tenemos ambos valores
        if [[ -n "$SRC_MAC" && -n "$FINAL_IP" ]]; then
            KEY="${SRC_MAC}-${FINAL_IP}"
            if [[ -n "${global_seen[$KEY]}" ]]; then
                continue
            fi
            global_seen[$KEY]=1

            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$FINAL_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')

            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"

            echo "[$IFACE] Binding encontrado: $FINAL_IP -> $SRC_MAC"
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

# Eliminar duplicados por IPv6
if command -v jq &> /dev/null; then
    jq 'with_entries(.value |= unique_by(.ipv6))' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
fi

# Mostrar resultado final
echo "[✓] Tabla final generada en: $BINDING_FILE"
cat "$BINDING_FILE"
