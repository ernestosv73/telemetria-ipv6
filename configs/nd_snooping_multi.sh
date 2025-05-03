#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
DURATION=30
TMP_DIR="/tmp/nd_snoop"
BINDING_FILE="/root/bindings.json"

echo "[*] Capturando mensajes ND (NS/NA) durante $DURATION segundos..."
mkdir -p "$TMP_DIR"

for IFACE in "${INTERFACES[@]}"; do
    tcpdump -i "$IFACE" -w "$TMP_DIR/$IFACE.pcap" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
done

sleep "$DURATION"
pkill tcpdump

echo "[*] Procesando paquetes ND..."
# Asegurar archivo de bindings
if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"

    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e |
    while read -r line; do
        echo "[*] Línea: $line"

        # Extraer MAC
        if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1]}"
        else
            SRC_MAC=""
        fi

        # Extraer IPv6
        if [[ "$line" =~ who\ has\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ tgt\ is\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[1]}"
        else
            IPV6=""
        fi

        # Guardar si es válido
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "Binding encontrado: $IPV6 -> $SRC_MAC en $IFACE"

            EXISTS=$(jq --arg ip "$IPV6" '.bindings[] | select(.ipv6 == $ip)' "$BINDING_FILE")
            if [ -z "$EXISTS" ]; then
                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$IFACE" --arg ts "$TIMESTAMP" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
            fi
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
