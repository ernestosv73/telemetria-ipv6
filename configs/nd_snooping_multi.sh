#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal y archivo inicial
mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Iniciando captura ND (Neighbor Solicitation/Advertisement) durante ${CAPTURE_DURATION} segundos..."
PIDS=()

# Iniciar capturas paralelas
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar a que terminen todas las capturas
for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null
done

echo "[*] Procesando paquetes ICMPv6..."

declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    INTERFACE_BINDINGS["$IFACE"]="[]"

    # Extraer información con tshark
    tshark -r "$FILE" -T fields \
        -e eth.src \
        -e ipv6.src \
        -e icmpv6.target \
        -e icmpv6.opt.linkaddr \
        | while read -r mac ip_src target lladdr; do

        FINAL_MAC="${lladdr:-$mac}"
        FINAL_IP=""

        for candidate in "$ip_src" "$target"; do
            if [[ -n "$candidate" && "$candidate" != "::" ]]; then
                FINAL_IP="$candidate"
                break
            fi
        done

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

# Eliminar duplicados
if command -v jq &> /dev/null; then
    jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
else
    echo "[!] jq no encontrado. No se eliminaron duplicados."
fi

# Mostrar resultado final
echo "[✓] Archivo JSON generado en: $BINDING_FILE"
cat "$BINDING_FILE"
