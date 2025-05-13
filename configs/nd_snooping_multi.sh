#!/bin/bash

# Configuración
INTERFACES=("e1-2" "e1-3" "e1-4")
OUTPUT_FILE="/root/ndp_bindings.json"
CAPTURE_DURATION=60
PCAP_DIR="/tmp/ndp_captures"
LOG_FILE="/var/log/ndp_monitor.log"

mkdir -p "$PCAP_DIR"
touch "$LOG_FILE"

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_event "Iniciando captura de mensajes ND/NA por $CAPTURE_DURATION segundos"
echo '{"bindings": []}' > "$OUTPUT_FILE"

declare -A PIDS          # 💡 Solución al error de subscript
declare -A BINDINGS_TABLE

# Iniciar capturas en paralelo
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    timeout $CAPTURE_DURATION tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null &
    PIDS["$IFACE"]=$!
    log_event "Capturando en $IFACE (PID: ${PIDS[$IFACE]})"
done

# Esperar que terminen todas las capturas
for IFACE in "${!PIDS[@]}"; do
    wait ${PIDS[$IFACE]}
    log_event "Captura completada en $IFACE"
done

# Procesar las capturas
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    tcpdump -nn -r "$PCAP_FILE" -e -vvv 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null | \
    while read -r line; do
        src_mac=$(echo "$line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1 | tr '[:upper:]' '[:lower:]')
        ipv6=$(echo "$line" | grep -oE '([a-f0-9:]{4,})' | grep ':' | head -1 | tr '[:upper:]' '[:lower:]')

        [[ -z "$src_mac" || -z "$ipv6" ]] && continue

        key="$IFACE,$ipv6"
        [[ -n "${BINDINGS_TABLE[$key]}" ]] && continue

        ip_type="global"
        [[ "$ipv6" =~ ^fe80:: ]] && ip_type="link-local"

        time_left=$((1800 - $(date +%s) % 1800))
        state="Valid"

        # Añadir a tabla hash
        BINDINGS_TABLE["$key"]=1

        # Usar jq para añadir al JSON
        tmp_json=$(mktemp)
        jq --arg iface "$IFACE" \
           --arg ip "$ipv6" \
           --arg mac "$src_mac" \
           --argjson time "$time_left" \
           --arg state "$state" \
           --arg type "$ip_type" \
           --arg time_str "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
           '.bindings += [{
               interface: $iface,
               ipv6_address: $ip,
               mac_address: $mac,
               time_left: $time,
               state: $state,
               ip_type: $type,
               last_seen: $time_str
           }]' "$OUTPUT_FILE" > "$tmp_json" && mv "$tmp_json" "$OUTPUT_FILE"

        log_event "Binding detectado: $IFACE $ipv6 -> $src_mac"
    done
done

# Mostrar tabla legible
echo -e "\nINTERFACE    IPV6-ADDRESS                             MAC-ADDRESS         TIME-LEFT STATE    TYPE"
echo "--------    --------------------------------------    -------------------  --------- -------- ---------"

jq -r '.bindings[] | [.interface, .ipv6_address, .mac_address, (.time_left|tostring), .state, .ip_type] | @tsv' "$OUTPUT_FILE" | \
while IFS=$'\t' read -r iface ip mac ttl state type; do
    printf "%-12s %-38s %-20s %-9s %-8s %-9s\n" "$iface" "$ip" "$mac" "$ttl" "$state" "$type"
done | sort -k1,1 -k2,2

log_event "Monitoreo ND completado. Resultados en $OUTPUT_FILE"
