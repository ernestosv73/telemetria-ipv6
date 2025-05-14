#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
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

echo "[*] Procesando paquetes ND..."
declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    PACKET_COUNT=$(tcpdump -nn -r "$FILE" 2>/dev/null | wc -l)
    if [[ "$PACKET_COUNT" -eq 0 ]]; then
        echo "[-] $IFACE no tiene paquetes ND, se omite."
        continue
    fi

    declare -A UNIQUE_BINDINGS=()

    while read -r line; do
        SRC_MAC=""
        IPV6=""

        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        elif [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            KEY="${IPV6}_${SRC_MAC}"
            if [[ -z "${UNIQUE_BINDINGS[$KEY]}" ]]; then
                echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
                BINDING_JSON=$(jq -n \
                    --arg mac "$SRC_MAC" \
                    --arg ip "$IPV6" \
                    --arg intf "$IFACE" \
                    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                    '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')
                UNIQUE_BINDINGS["$KEY"]="$BINDING_JSON"
            fi
        fi
    done < <(tcpdump -nn -r "$FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)

    # Guardar los bindings de esta interfaz
    if [[ ${#UNIQUE_BINDINGS[@]} -gt 0 ]]; then
        INTERFACE_JSON=$(printf '%s\n' "${UNIQUE_BINDINGS[@]}" | jq -s '.')
        jq --arg intf "$IFACE" --argjson data "$INTERFACE_JSON" '. + {($intf): $data}' "$BINDING_FILE" > "$BINDING_FILE.tmp" && mv "$BINDING_FILE.tmp" "$BINDING_FILE"
    fi
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
