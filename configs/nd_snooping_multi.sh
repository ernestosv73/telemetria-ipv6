#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
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
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null &
    PIDS+=($!)
done

# Esperar finalización de todos los procesos tcpdump
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

declare -A UNIQUE_KEYS
declare -a BINDINGS_JSON

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    # Leer paquetes ND del archivo pcap
    tcpdump -nn -r "$FILE" -e -vvv 2>/dev/null | while read -r line; do
        MAC=$(echo "$line" | grep -oE 'src [0-9a-f:]{17}' | awk '{print $2}')
        IP=$(echo "$line" | grep -oE '([0-9a-f]{0,4}:){2,7}[0-9a-f]{1,4}')
        
        if [[ -n "$MAC" && -n "$IP" ]]; then
            KEY="${MAC}_${IP}_${IFACE}"
            if [[ -z "${UNIQUE_KEYS[$KEY]}" ]]; then
                UNIQUE_KEYS[$KEY]=1
                echo "[$IFACE] Binding encontrado: $IP -> $MAC"

                BINDING_JSON=$(jq -n \
                    --arg mac "$MAC" \
                    --arg ip "$IP" \
                    --arg intf "$IFACE" \
                    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                    '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')

                BINDINGS_JSON+=("$BINDING_JSON")
            fi
        fi
    done
done

# Guardar el resultado final
if [ ${#BINDINGS_JSON[@]} -gt 0 ]; then
    printf '%s\n' "${BINDINGS_JSON[@]}" | jq -s '{"bindings": .}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
