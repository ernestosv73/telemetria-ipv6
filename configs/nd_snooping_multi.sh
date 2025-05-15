#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal
mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

declare -A BINDINGS
for IFACE in "${INTERFACES[@]}"; do
    BINDINGS["$IFACE"]="[]"
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    # Procesar cada paquete con formato más robusto
    while read -r line; do
        SRC_MAC=""
        SRC_IP=""
        TGT_IP=""
        TYPE=""

        # Extraer MAC origen (mejor expresión regular)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IP origen (formato más seguro)
        if [[ "$line" =~ IP6[[:space:]]+([0-9a-fA-F:]+)[[:space:]]+> ]]; then
            SRC_IP="${BASH_REMATCH[1],,}"
        fi

        # Determinar tipo de mensaje
        if [[ "$line" =~ "ICMP6, neighbor solicitation" ]]; then
            TYPE="NS"
            if [[ "$line" =~ "who has ([0-9a-fA-F:]+)" ]]; then
                TGT_IP="${BASH_REMATCH[1],,}"
            fi
        elif [[ "$line" =~ "ICMP6, router solicitation" ]]; then
            TYPE="RS"
            TGT_IP="$SRC_IP"
        elif [[ "$line" =~ "ICMP6, router advertisement" ]]; then
            TYPE="RA"
            TGT_IP="$SRC_IP"
        fi

        # Registrar binding si tenemos información válida
        if [[ -n "$TGT_IP" ]]; then
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            MAC_TO_USE="${SRC_MAC:-00:00:00:00:00:00}"
            
            BINDING=$(jq -n \
                --arg mac "$MAC_TO_USE" \
                --arg ipv6 "$TGT_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
            
            CURRENT=$(echo "${BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            BINDINGS["$IFACE"]="$CURRENT"
            
            echo "[$IFACE] Registrado: $TGT_IP -> $MAC_TO_USE ($TYPE)"
        fi

    done < <(tcpdump -nn -r "$FILE" -v 'icmp6' 2>/dev/null)
done

# Generar JSON final
echo "{" > "$BINDING_FILE"
FIRST=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST" -eq 0 ]; then
        echo "," >> "$BINDING_FILE"
    else
        FIRST=0
    fi
    echo -n "  \"$IFACE\": ${BINDINGS[$IFACE]}" >> "$BINDING_FILE"
done
echo -e "\n}" >> "$BINDING_FILE"

# Limpiar duplicados
jq 'walk(if type == "array" then unique_by(.ipv6) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Resultados guardados en: $BINDING_FILE"
jq . "$BINDING_FILE"
