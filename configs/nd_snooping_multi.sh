#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
rm -f "$BINDING_FILE"
echo '{}' > "$BINDING_FILE"

# Iniciar capturas en paralelo
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar a que terminen
for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null
done

echo "[*] Procesando paquetes ICMPv6..."

FINAL_JSON=$(jq -n '{}')

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    BINDINGS_FOR_IFACE="[]"

    tcpdump -nn -e -r "$FILE" 2>/dev/null | while read -r line; do
        SRC_MAC=""
        FINAL_IP=""

        # Extraer MAC origen
        if [[ "$line" =~ ([0-9a-fA-F:]{17}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IPv6 destino u origen
        if [[ "$line" =~ who\ has\ ([0-9a-fA-F:\.\%]+) ]]; then
            FINAL_IP="${BASH_REMATCH[1],,}"
        elif [[ "$line" =~ from\ ([0-9a-fA-F:\.\%]+) ]]; then
            FINAL_IP="${BASH_REMATCH[1],,}"
        fi

        # Registrar binding si tenemos ambos valores
        if [[ -n "$SRC_MAC" && -n "$FINAL_IP" ]]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$FINAL_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')

            BINDINGS_FOR_IFACE=$(echo "$BINDINGS_FOR_IFACE" | jq --argjson binding "$BINDING" '. + [$binding]')
            echo "[+] Interface: $IFACE | MAC: $SRC_MAC | IPv6: $FINAL_IP"
        fi
    done

    # Agregar bindings por interfaz al JSON final
    FINAL_JSON=$(echo "$FINAL_JSON" | jq --argjson data "$BINDINGS_FOR_IFACE" --arg intf "$IFACE" '. + {($intf): $data}')
done

# Eliminar duplicados por IPv6 dentro de cada interfaz
FINAL_JSON=$(echo "$FINAL_JSON" | jq 'with_entries(.value |= unique_by(.ipv6))')

# Guardar archivo JSON final
echo "$FINAL_JSON" > "$BINDING_FILE"

echo "[✓] Archivo JSON generado en: $BINDING_FILE"
cat "$BINDING_FILE"
