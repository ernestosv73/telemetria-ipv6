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

log_event "Iniciando captura ND/NA por $CAPTURE_DURATION segundos"
echo '{"bindings": []}' > "$OUTPUT_FILE"

declare -A PIDS
declare -A BINDINGS_TABLE

# Captura por interfaz
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    timeout $CAPTURE_DURATION tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null &
    PIDS["$IFACE"]=$!
    log_event "Capturando en $IFACE (PID: ${PIDS[$IFACE]})"
done

# Esperar a que terminen
for IFACE in "${!PIDS[@]}"; do
    wait ${PIDS[$IFACE]}
    log_event "Captura completada en $IFACE"
done

# Procesamiento
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    tcpdump -nn -r "$PCAP_FILE" -e -vvv 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null | \
    while read -r line; do
        src_mac=$(echo "$line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1 | tr '[:upper:]' '[:lower:]')
        ipv6=$(echo "$line" | grep -oE '([a-f0-9:]{4,})' | grep ':' | head -1 | tr '[:upper:]' '[:lower:]')

        [[ -z "$src_mac" || -z "$ipv6" ]] && continue

        key="$IFACE,$ipv6"
        [[ -n "${BINDINGS_TABLE[$key]}" ]] && continue

        BINDINGS_TABLE["$key"]=1

        ip_type="global"
        [[ "$ipv6" =~ ^fe80:: ]] && ip_type="link-local"
        time_left=$((1800 - $(date +%s) % 1800))
        state="Valid"

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

        log_event "Binding registrado: $IFACE $ipv6 -> $src_mac"
    done
done

log_event "Archivo JSON generado en $OUTPUT_FILE"
