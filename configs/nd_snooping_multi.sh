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
    # Captura con timeout por interfaz
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Espera que todos terminen
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
declare -a ALL_BINDINGS=()

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    # Validar que haya al menos 1 paquete en el archivo
    PACKET_COUNT=$(tcpdump -nn -r "$FILE" 2>/dev/null | wc -l)
    if [[ "$PACKET_COUNT" -eq 0 ]]; then
        echo "[-] $IFACE no tiene paquetes ND, se omite."
        continue
    fi

    # Procesar solo si hay tráfico ND real
    while read -r line; do
        SRC_MAC=""
        IPV6=""

        # Extraer MAC (la primera encontrada)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IPv6 (NS: who has / NA: tgt is)
        if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        elif [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        fi

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

# Consolidar y eliminar duplicados por IP + interfaz
if [ ${#ALL_BINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${ALL_BINDINGS[@]}" | jq -s '{"bindings": (unique_by(.ipv6, .interface))}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
