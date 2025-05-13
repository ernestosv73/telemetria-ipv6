#!/bin/bash

# Configuración
INTERFACES=("e1-2" "e1-3" "e1-4")
OUTPUT_FILE="/root/ndp_bindings.json"
CAPTURE_DURATION=60
PCAP_DIR="/tmp/ndp_captures"
LOG_FILE="/var/log/ndp_monitor.log"

# Crear directorios necesarios
mkdir -p "$PCAP_DIR"
touch "$LOG_FILE"

# Función para registrar eventos
log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Inicializar archivos
echo '{"bindings": []}' > "$OUTPUT_FILE"
> "$LOG_FILE"

# Capturar tráfico ND/NA
log_event "Iniciando captura de mensajes ND/NA por $CAPTURE_DURATION segundos"
declare -A CAPTURE_PIDS

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    timeout $CAPTURE_DURATION tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        'icmp6 && (ip6[40] == 135 || ip6[40] == 136)' 2>/dev/null &
    CAPTURE_PIDS["$IFACE"]=$!
    log_event "Capturando en $IFACE (PID: ${CAPTURE_PIDS[$IFACE]})"
done

# Esperar finalización de capturas
for IFACE in "${!CAPTURE_PIDS[@]}"; do
    wait ${CAPTURE_PIDS["$IFACE"]}
    log_event "Captura completada en $IFACE"
done

# Procesar capturas y generar tabla de bindings
declare -A BINDINGS_TABLE
declare -A DAD_STATUS

process_pcap() {
    local IFACE=$1
    local PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    
    # Verificar si el archivo existe y no está vacío
    if [[ ! -s "$PCAP_FILE" ]]; then
        log_event "No se capturaron paquetes en $IFACE"
        return
    fi
    
    tcpdump -nn -r "$PCAP_FILE" -e 'icmp6 && (ip6[40] == 135 || ip6[40] == 136)' 2>/dev/null | \
    while read -r line; do
        # Extraer MAC e IPv6 con patrones más precisos
        local src_mac=$(echo "$line" | grep -oP '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 | tr '[:upper:]' '[:lower:]')
        local ipv6=$(echo "$line" | grep -oP '(who has|tgt is) (\K[0-9a-fA-F:]+)' | head -1 | tr '[:upper:]' '[:lower:]')
        
        if [[ -n "$src_mac" && -n "$ipv6" ]]; then
            # Verificar tipo de dirección
            local ip_type="global"
            [[ "$ipv6" =~ ^fe80:: ]] && ip_type="link-local"
            
            # Verificar estado DAD
            local dad_state="valid"
            if [[ "$line" =~ "duplicate" ]]; then
                dad_state="duplicate"
                DAD_STATUS["$ipv6"]="duplicate"
            fi
            
            # Si ya fue marcado como duplicado, mantener el estado
            [[ -n "${DAD_STATUS[$ipv6]}" && "${DAD_STATUS[$ipv6]}" == "duplicate" ]] && dad_state="duplicate"
            
            # Calcular tiempo restante (default 1800s - 30min)
            local time_left=$((1800 - $(date +%s) % 1800))
            
            # Crear clave única por interfaz + ipv6 + mac
            local KEY="${IFACE}-${ipv6}-${src_mac}"
            
            # Solo agregar si no existe ya este binding específico
            if [[ -z "${BINDINGS_TABLE[$KEY]}" ]]; then
                BINDINGS_TABLE["$KEY"]=$(jq -n \
                    --arg iface "$IFACE" \
                    --arg ip "$ipv6" \
                    --arg mac "$src_mac" \
                    --arg time_left "$time_left" \
                    --arg state "$dad_state" \
                    --arg ip_type "$ip_type" \
                    '{
                        interface: $iface,
                        ipv6_address: $ip,
                        mac_address: $mac,
                        time_left: $time_left,
                        state: $state,
                        ip_type: $ip_type,
                        last_seen: now|todate
                    }')
                
                log_event "Binding detectado: $IFACE $ipv6 -> $src_mac ($dad_state)"
            fi
        fi
    done
}

# Procesar cada archivo pcap
for IFACE in "${INTERFACES[@]}"; do
    process_pcap "$IFACE"
done

# Generar salida JSON combinando todos los bindings
if [[ ${#BINDINGS_TABLE[@]} -gt 0 ]]; then
    # Crear array JSON temporal
    echo -n "[" > "${OUTPUT_FILE}.tmp"
    FIRST=1
    for KEY in "${!BINDINGS_TABLE[@]}"; do
        if [[ $FIRST -eq 1 ]]; then
            FIRST=0
        else
            echo -n "," >> "${OUTPUT_FILE}.tmp"
        fi
        echo -n "${BINDINGS_TABLE[$KEY]}" >> "${OUTPUT_FILE}.tmp"
    done
    echo -n "]" >> "${OUTPUT_FILE}.tmp"
    
    # Crear JSON final con estructura correcta
    jq -n '{bindings: $bindings}' --slurpfile bindings "${OUTPUT_FILE}.tmp" > "$OUTPUT_FILE"
    rm "${OUTPUT_FILE}.tmp"
else
    echo '{"bindings": []}' > "$OUTPUT_FILE"
    log_event "No se encontraron bindings ND válidos"
fi

# Generar tabla legible
echo -e "\nINTERFACE    IPV6-ADDRESS                             MAC-ADDRESS         TIME-LEFT STATE    TYPE"
echo "--------  ------------------------------------  -------------------  --------- -------- ---------"
for KEY in "${!BINDINGS_TABLE[@]}"; do
    DATA="${BINDINGS_TABLE[$KEY]}"
    printf "%-8s  %-38s  %-18s  %-8s %-8s %-9s\n" \
        "$(echo "$DATA" | jq -r '.interface')" \
        "$(echo "$DATA" | jq -r '.ipv6_address')" \
        "$(echo "$DATA" | jq -r '.mac_address')" \
        "$(echo "$DATA" | jq -r '.time_left')" \
        "$(echo "$DATA" | jq -r '.state')" \
        "$(echo "$DATA" | jq -r '.ip_type')"
done | sort -k1,1 -k2,2

log_event "Monitoreo ND completado. Resultados en $OUTPUT_FILE"
echo "Resultados guardados en $OUTPUT_FILE"
