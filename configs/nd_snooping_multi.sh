#!/bin/bash

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

# Iniciar JSON manualmente
echo '{"bindings": [' > "$OUTPUT_FILE"

declare -A BINDINGS_TABLE
FIRST=1

log_event "Iniciando captura de mensajes ND/NA por $CAPTURE_DURATION segundos"

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    timeout $CAPTURE_DURATION tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null &
    PIDS[$IFACE]=$!
    log_event "Capturando en $IFACE (PID: ${PIDS[$IFACE]})"
done

for IFACE in "${!PIDS[@]}"; do
    wait ${PIDS[$IFACE]}
    log_event "Captura completada en $IFACE"
done

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$PCAP_DIR/${IFACE}_ndp.pcap"
    
    tcpdump -nn -r "$PCAP_FILE" -e -vvv 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null | \
    while read -r line; do
        src_mac=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if ($i ~ /([0-9a-f]{2}:){5}[0-9a-f]{2}/) {print $i; exit}}' | tr '[:upper:]' '[:lower:]')
        ipv6=$(echo "$line" | grep -oE '([a-f0-9:]{4,})' | grep ':' | head -1 | tr '[:upper:]' '[:lower:]')

        [[ -z "$src_mac" || -z "$ipv6" ]] && continue

        key="$IFACE,$ipv6"
        [[ -n "${BINDINGS_TABLE[$key]}" ]] && continue

        ip_type="global"
        [[ "$ipv6" =~ ^fe80:: ]] && ip_type="link-local"

        time_left=$((1800 - $(date +%s) % 1800))
        state="Valid"

        BINDINGS_TABLE["$key"]=1

        [[ $FIRST -eq 0 ]] && echo "," >> "$OUTPUT_FILE"
        FIRST=0

        echo "  {" >> "$OUTPUT_FILE"
        echo "    \"interface\": \"$IFACE\"," >> "$OUTPUT_FILE"
        echo "    \"ipv6_address\": \"$ipv6\"," >> "$OUTPUT_FILE"
        echo "    \"mac_address\": \"$src_mac\"," >> "$OUTPUT_FILE"
        echo "    \"time_left\": $time_left," >> "$OUTPUT_FILE"
        echo "    \"state\": \"$state\"," >> "$OUTPUT_FILE"
        echo "    \"ip_type\": \"$ip_type\"," >> "$OUTPUT_FILE"
        echo "    \"last_seen\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"" >> "$OUTPUT_FILE"
        echo -n "  }" >> "$OUTPUT_FILE"
    done
done

echo "]}" >> "$OUTPUT_FILE"

# Tabla de salida humana
echo -e "\nINTERFACE    IPV6-ADDRESS                             MAC-ADDRESS         TIME-LEFT STATE    TYPE"
echo "--------  ------------------------------------  -------------------  --------- -------- ---------"
for KEY in "${!BINDINGS_TABLE[@]}"; do
    IFS=',' read -r IFACE IPV6 <<< "$KEY"
    grep -A 7 "\"ipv6_address\": \"$IPV6\"" "$OUTPUT_FILE" | awk '
        /"mac_address"/ {gsub(/"|,/, "", $2); mac=$2}
        /"time_left"/ {gsub(/,/, "", $2); time=$2}
        /"state"/ {gsub(/"|,/, "", $2); state=$2}
        /"ip_type"/ {gsub(/"|,/, "", $2); type=$2}
        END {
            printf "%-10s %-38s %-20s %-9s %-8s %-9s\n", "'$IFACE'", "'$IPV6'", mac, time, state, type
        }'
done | sort -k1,1

log_event "Monitoreo ND completado. Resultados en $OUTPUT_FILE"
