#!/bin/bash

# Configuración
INTERFACES=("e1-2" "e1-3" "e1-4")
OUTPUT_FILE="/root/ndp_bindings.json"
CAPTURE_DURATION=60  # Duración en segundos
PCAP_DIR="/tmp/ndp_captures"
LOG_FILE="/var/log/ndp_monitor.log"

# Crear directorios necesarios
mkdir -p "$PCAP_DIR"
touch "$LOG_FILE"

# Función para registrar eventos
log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Inicializar archivo JSON
echo '{"bindings": []}' > "$OUTPUT_FILE"

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
declare -A DAD_STATUS  # Para seguimiento de DAD (Duplicate Address Detection)

process_pcap() {
    local IFACE=$1
    local PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    
    tcpdump -nn -r "$PCAP_FILE" -e 'icmp6 && (ip6[40] == 135 || ip6[40] == 136)' 2>/dev/null | \
    while read -r line; do
        # Extraer MAC e IPv6
        local src_mac=$(echo "$line" | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1 | tr '[:upper:]' '[:lower:]')
        local ipv6=$(echo "$line" | grep -o -E '(who has|tgt is) ([0-9a-fA-F:]+)' | awk '{print $3}' | tr '[:upper:]' '[:lower:]')
        
        if [[ -n "$src_mac" && -n "$ipv6" ]]; then
            # Verificar si es una dirección link-local o global
            local ip_type="global"
            [[ "$ipv6" =~ ^fe80:: ]] && ip_type="link-local"
            
            # Verificar estado DAD (si es mensaje NA con flag duplicate)
            local dad_state="valid"
            if [[ "$line" =~ "duplicate" ]]; then
                dad_state="duplicate"
                DAD_STATUS["$ipv6"]="duplicate"
            fi
            
            # Si ya fue marcado como duplicado, mantener el estado
            [[ -n "${DAD_STATUS[$ipv6]}" && "${DAD_STATUS[$ipv6]}" == "duplicate" ]] && dad_state="duplicate"
            
            # Calcular tiempo restante (default 1800s - 30min)
            local time_left=$((1800 - $(date +%s) % 1800))
            
            # Actualizar tabla de bindings
            BINDINGS_TABLE["$IFACE,$ipv6"]=$(jq -n \
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
    done
}

# Procesar cada archivo pcap
for IFACE in "${INTERFACES[@]}"; do
    process_pcap "$IFACE"
done

# Generar salida JSON
echo "{" > "$OUTPUT_FILE"
echo '"bindings": [' >> "$OUTPUT_FILE"

FIRST=1
for KEY in "${!BINDINGS_TABLE[@]}"; do
    if [[ $FIRST -eq 1 ]]; then
        FIRST=0
    else
        echo "," >> "$OUTPUT_FILE"
    fi
    echo -n "${BINDINGS_TABLE[$KEY]}" >> "$OUTPUT_FILE"
done

echo "]}" >> "$OUTPUT_FILE"

# Generar tabla legible (formato similar a NDPMon)
echo -e "\nINTERFACE    IPV6-ADDRESS                             MAC-ADDRESS         TIME-LEFT STATE    TYPE"
echo "--------  ------------------------------------  -------------------  --------- -------- ---------"
for KEY in "${!BINDINGS_TABLE[@]}"; do
    IFS=',' read -r IFACE IPV6 <<< "$KEY"
    DATA="${BINDINGS_TABLE[$KEY]}"
    
    printf "%-8s  %-38s  %-18s  %-8s %-8s %-9s\n" \
        "$IFACE" \
        "$(echo "$DATA" | jq -r '.ipv6_address')" \
        "$(echo "$DATA" | jq -r '.mac_address')" \
        "$(echo "$DATA" | jq -r '.time_left')" \
        "$(echo "$DATA" | jq -r '.state')" \
        "$(echo "$DATA" | jq -r '.ip_type')"
done | sort -k1,1 -k5,5 -k6,6

log_event "Monitoreo ND completado. Resultados en $OUTPUT_FILE"
