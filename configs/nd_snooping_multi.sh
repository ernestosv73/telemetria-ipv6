#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
mkdir -p "$TMP_DIR"

if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[*] Capturando ND en interfaces durante 30 segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout 30 tcpdump -i "$IFACE" -vv ip6 and 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e > "$FILE" &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"

    # Lectura de paquetes con más depuración
    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e | while read -r line; do
        echo "[*] Paquete capturado: $line"  # Agregamos más depuración para ver el contenido del paquete

        if [[ "$line" =~ ([0-9a-f:]{17})\  >\ 33:33:ff:([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1]}"
        fi

        # Ajustar la extracción de IPv6
        if [[ "$line" =~ ICMP6,\ neighbor\ solicitation,\ length ]]; then
            IPV6=$(echo "$line" | grep -oP 'who\ has\s+([0-9a-f:]+::[0-9a-f:]+)' | sed 's/who has //')
        elif [[ "$line" =~ ICMP6,\ neighbor\ advertisement,\ length ]]; then
            IPV6=$(echo "$line" | grep -oP 'target\s+([0-9a-f:]+::[0-9a-f:]+)' | sed 's/target //')
        fi

        # Si se encuentran ambos, agregar el binding
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "Binding encontrado: $IPV6 -> $SRC_MAC"  # Depuración: Imprimir los bindings encontrados

            EXISTS=$(jq --arg ip "$IPV6" '.bindings[] | select(.ipv6 == $ip)' "$BINDING_FILE")
            if [ -z "$EXISTS" ]; then
                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$INTF" --arg ts "$TIMESTAMP" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
            fi

            SRC_MAC=""
            IPV6=""
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
