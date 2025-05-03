#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30
LOCK_FILE="/tmp/nd_snooping.lock"

# Configuración de bloqueo para evitar ejecuciones concurrentes
exec 200>$LOCK_FILE
flock -n 200 || { echo "El script ya está en ejecución"; exit 1; }

# Función para limpieza al salir
cleanup() {
    rm -f "$TEMP_FILE"
    flock -u 200
}
trap cleanup EXIT

mkdir -p "$TMP_DIR"

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
TEMP_FILE=$(mktemp)

# Procesar cada interfaz y acumular bindings
declare -A BINDINGS_MAP

# Cargar bindings existentes primero
while IFS= read -r line; do
    if [[ "$line" =~ \"ipv6\":\"([^\"]+)\".*\"interface\":\"([^\"]+)\" ]]; then
        BINDINGS_MAP["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    fi
done < <(jq -c '.bindings[]' "$BINDING_FILE")

# Procesar nuevas capturas
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    
    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null | while read -r line; do
        SRC_MAC=""
        IPV6=""
        
        # Extraer MAC origen (formato mejorado)
        if [[ "$line" =~ ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer IPv6 (versión robusta)
        if [[ "$line" =~ (who has|tgt is)\ ([0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[2],,}"
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            
            # Actualizar el mapa de bindings
            BINDINGS_MAP["$IPV6"]="$IFACE"
            
            # Añadir al archivo temporal
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            echo "{\"mac\":\"$SRC_MAC\",\"ipv6\":\"$IPV6\",\"interface\":\"$IFACE\",\"timestamp\":\"$TIMESTAMP\"}" >> "$TEMP_FILE"
        fi
    done
done

# Generar archivo final consolidado
{
    echo '{"bindings": ['
    first=true
    while IFS= read -r line; do
        if $first; then
            first=false
        else
            echo ","
        fi
        echo -n "$line"
    done < "$TEMP_FILE"
    echo ']}'
} | jq '{
    bindings: [
        .bindings[] | 
        select(.ipv6 != null and .mac != null) |
        {
            mac: .mac,
            ipv6: .ipv6,
            interface: .interface,
            timestamp: .timestamp
        }
    ] | unique_by(.ipv6)
}' > "$BINDING_FILE"

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
