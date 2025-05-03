#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30
LOCK_FILE="/tmp/nd_snooping.lock"

# Bloqueo para evitar ejecuciones concurrentes
exec 200>$LOCK_FILE
flock -n 200 || { echo "Script ya en ejecución"; exit 1; }

# Configuración inicial
mkdir -p "$TMP_DIR"
cleanup() {
    rm -f "${TMP_DIR}/combined.json"
    flock -u 200
}
trap cleanup EXIT

# Inicializar archivo JSON si no existe
if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

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

# Procesar cada interfaz y generar archivos temporales individuales
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    OUTPUT="$TMP_DIR/${IFACE}_bindings.json"
    
    echo '{"bindings": []}' > "$OUTPUT"
    
    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null | while read -r line; do
        SRC_MAC=""
        IPV6=""
        
        # Extraer MAC origen (versión mejorada)
        if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}) ]]; then
            SRC_MAC=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
        fi

        # Extraer IPv6 (captura tanto NS como NA)
        if [[ "$line" =~ (who has|tgt is)\ ([0-9a-fA-F:]+) ]]; then
            IPV6=$(echo "${BASH_REMATCH[2]}" | tr '[:upper:]' '[:lower:]')
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            
            # Crear JSON para este binding
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$IFACE" --arg ts "$TIMESTAMP" \
               '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
               "$OUTPUT" > "${OUTPUT}.tmp" && mv "${OUTPUT}.tmp" "$OUTPUT"
        fi
    done
done

# Combinar todos los bindings y eliminar duplicados (manteniendo el más reciente)
jq -n '{bindings: [inputs.bindings[]]}' "${TMP_DIR}/"*_bindings.json | \
jq '
  .bindings |= group_by(.ipv6) | 
  .bindings |= map(max_by(.timestamp)) | 
  .bindings |= sort_by(.ipv6)
' > "${TMP_DIR}/combined.json"

# Actualizar archivo principal conservando bindings no detectados recientemente
jq -s '
  .[0].bindings as $old |
  .[1].bindings as $new |
  ($old + $new) | 
  group_by(.ipv6) | 
  map(max_by(.timestamp)) | 
  {bindings: .}
' "$BINDING_FILE" "${TMP_DIR}/combined.json" > "${BINDING_FILE}.tmp" && \
mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
