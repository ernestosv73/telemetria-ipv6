#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"

# Inicializar archivo JSON con estructura correcta
echo '{"bindings": []}' > "$BINDING_FILE"

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
# Procesar cada interfaz y acumular bindings
declare -a ALL_BINDINGS=()

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    # Procesar paquetes para esta interfaz
    while read -r line; do
        SRC_MAC=""
        IPV6=""
        
        # Extraer MAC origen (formato más robusto)
        if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}" # Convertir a minúsculas
        fi

        # Extraer IPv6 (versión mejorada)
        if [[ "$line" =~ (who has|tgt is)\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[2],,}"
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            
            # Crear objeto JSON para este binding
            BINDING_JSON=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$IFACE" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interface: $intf, timestamp: $ts}')
            
            ALL_BINDINGS+=("$BINDING_JSON")
        fi
    done < <(tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null)
done

# Combinar todos los bindings y eliminar duplicados
if [ ${#ALL_BINDINGS[@]} -gt 0 ]; then
    printf '%s\n' "${ALL_BINDINGS[@]}" | jq -s '{"bindings": (. | unique_by(.ipv6))}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
