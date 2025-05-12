#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"

# Inicializar archivo de bindings si no existe
if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[*] Capturando mensajes ND (NS y NA)..."
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

echo "[*] Procesando paquetes capturados..."
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e | while read -r line; do
        # Extraer MAC origen
        if [[ "$line" =~ ([0-9a-f]{2}(:[0-9a-f]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1]}"
        else
            continue
        fi

        # Extraer dirección IPv6 del campo who has / tgt is
        if [[ "$line" =~ who\ has\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ tgt\ is\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[1]}"
        else
            continue
        fi

        # Validar si ya existe esa asociación
        EXISTS=$(jq --arg ip "$IPV6" --arg intf "$IFACE" '.bindings[] | select(.ipv6 == $ip and .interface == $intf)' "$BINDING_FILE")
        if [ -z "$EXISTS" ]; then
            echo "Aprendido: $IPV6 -> $SRC_MAC en $IFACE"
            jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$IFACE" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
        fi
    done
done

echo "[✓] Bindings generados:"
jq . "$BINDING_FILE"
