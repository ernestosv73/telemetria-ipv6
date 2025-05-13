#!/bin/bash

# Configuración
INTERFACES=("e1-2" "e1-3" "e1-4")
OUTPUT_FILE="/root/ndp_bindings.json"
CAPTURE_DURATION=30  # Reducido para pruebas
PCAP_DIR="/tmp/ndp_captures"
LOG_FILE="/var/log/ndp_monitor.log"

# Limpieza inicial
mkdir -p "$PCAP_DIR"
rm -f "$PCAP_DIR"/*.pcap
> "$LOG_FILE"
> "$OUTPUT_FILE"

# Función de logging mejorada
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Función para extraer MAC e IPv6 de forma robusta
extract_nd_info() {
    local line="$1"
    local src_mac=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 | tr '[:upper:]' '[:lower:]')
    local ipv6=$(echo "$line" | grep -oE '(who has|tgt is) ([0-9a-fA-F:]+)' | awk '{print $3}' | tr '[:upper:]' '[:lower:]')
    echo "$src_mac $ipv6"
}

# Captura de paquetes ND
log "Iniciando captura ND en interfaces: ${INTERFACES[*]}"
for IFACE in "${INTERFACES[@]}"; do
    timeout $CAPTURE_DURATION tcpdump -i "$IFACE" -w "$PCAP_DIR/${IFACE}.pcap" \
        'icmp6 && (ip6[40] == 135 || ip6[40] == 136)' 2>/dev/null &
done
wait

# Procesamiento de capturas
declare -A BINDINGS
declare -i BINDING_COUNT=0

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}.pcap"
    
    if [[ ! -s "$PCAP_FILE" ]]; then
        log "No se capturaron paquetes en $IFACE"
        continue
    fi

    log "Procesando $PCAP_FILE"
    tcpdump -nn -r "$PCAP_FILE" -e 2>/dev/null | while read -r line; do
        read -r src_mac ipv6 <<< $(extract_nd_info "$line")
        
        if [[ -n "$src_mac" && -n "$ipv6" ]]; then
            # Determinar tipo de dirección
            if [[ "$ipv6" =~ ^fe80:: ]]; then
                type="link-local"
            else
                type="global"
            fi

            # Verificar estado DAD
            if [[ "$line" =~ duplicate ]]; then
                state="duplicate"
            else
                state="valid"
            fi

            # Crear clave única por interfaz + MAC + IPv6
            KEY="${IFACE}-${src_mac}-${ipv6}"

            if [[ -z "${BINDINGS[$KEY]}" ]]; then
                BINDING_JSON=$(jq -n \
                    --arg iface "$IFACE" \
                    --arg ip "$ipv6" \
                    --arg mac "$src_mac" \
                    --arg state "$state" \
                    --arg type "$type" \
                    '{
                        interface: $iface,
                        ipv6_address: $ip,
                        mac_address: $mac,
                        state: $state,
                        type: $type,
                        timestamp: now|todate
                    }')

                BINDINGS["$KEY"]="$BINDING_JSON"
                ((BINDING_COUNT++))
                log "Nuevo binding: $IFACE $ipv6 -> $src_mac ($state)"
            fi
        fi
    done
done

# Generar archivo JSON final
if [[ $BINDING_COUNT -gt 0 ]]; then
    echo -n "[" > "$OUTPUT_FILE"
    FIRST=true
    for KEY in "${!BINDINGS[@]}"; do
        if $FIRST; then
            FIRST=false
        else
            echo -n "," >> "$OUTPUT_FILE"
        fi
        echo -n "${BINDINGS[$KEY]}" >> "$OUTPUT_FILE"
    done
    echo "]" >> "$OUTPUT_FILE"
    
    # Reformatear con jq para validación
    jq '{bindings: .}' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    
    log "Se encontraron $BINDING_COUNT bindings. Resultados en $OUTPUT_FILE"
else
    echo '{"bindings": []}' > "$OUTPUT_FILE"
    log "No se encontraron bindings ND válidos"
fi

# Mostrar resultados en tabla
if [[ $BINDING_COUNT -gt 0 ]]; then
    echo -e "\nINTERFACE  IPV6-ADDRESS                           MAC-ADDRESS         STATE      TYPE"
    echo "--------  ------------------------------------  -------------------  ---------  ----------"
    for KEY in "${!BINDINGS[@]}"; do
        DATA="${BINDINGS[$KEY]}"
        printf "%-8s  %-38s  %-18s  %-9s  %-10s\n" \
            "$(echo "$DATA" | jq -r '.interface')" \
            "$(echo "$DATA" | jq -r '.ipv6_address')" \
            "$(echo "$DATA" | jq -r '.mac_address')" \
            "$(echo "$DATA" | jq -r '.state')" \
            "$(echo "$DATA" | jq -r '.type')"
    done | sort
fi
