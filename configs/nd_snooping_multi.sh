#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo '{"bindings": []}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Espera que todos los procesos terminen
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
declare -a ALL_BINDINGS=()

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"

    while read -r line; do
        SRC_MAC=""
        IPV6=""

        # Extraer MAC de la línea (después de "src", o la primera MAC del frame)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"  # minusculas
        fi

        # Extraer dirección IPv6 (NS -> "who has", NA -> "tgt is")
        if [[ "$line" =~ "who has" ]]; then
            if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        elif [[ "$line" =~ "tgt is" ]]; then
            if [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
                IPV6="${BASH_REMATCH[1],,}"
            fi
        fi

        # Si se extrajeron ambos valores, registrar
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"

            BINDING_JSON=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$IFACE" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')

            ALL_BINDINGS+=("$BINDING_JSON")
        fi

    done < <(tcpdump -nn -r "$FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)
done

# Eliminar duplicados por IP + interfaz
if [ ${#ALL_BINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${ALL_BINDINGS[@]}" | jq -s '{"bindings": (unique_by(.ipv6, .interface))}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
