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
declare -A BINDING_MAP  # Usamos un array asociativo para evitar duplicados

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    # Procesar paquetes para esta interfaz
    while read -r line; do
        SRC_MAC=""
        IPV6=""
        PORT=$(echo "$IFACE" | grep -o -E '[0-9]+$')  # Extraer número de puerto de la interfaz
        
        # Extraer MAC origen (formato más robusto)
        if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}" # Convertir a minúsculas
        fi

        # Extraer IPv6 (versión mejorada)
        if [[ "$line" =~ (who has|tgt is)\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[2],,}"
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC (Puerto: $PORT)"
            
            # Usamos la IPv6 como clave para evitar duplicados
            BINDING_MAP["$IPV6"]=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ip "$IPV6" \
                --arg intf "$IFACE" \
                --arg port "$PORT" \
                --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                '{mac: $mac, ipv6: $ip, interface: $intf, port: $port, timestamp: $ts}')
        fi
    done < <(tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null)
done

# Convertir el mapa asociativo a array JSON
if [ ${#BINDING_MAP[@]} -gt 0 ]; then
    printf '%s\n' "${BINDING_MAP[@]}" | jq -s '{"bindings": .}' > "$BINDING_FILE"
else
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
