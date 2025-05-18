#!/bin/sh

OUTPUT_DIR="/data"
mkdir -p "$OUTPUT_DIR"

TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"
NDP_CACHE="/tmp/ndp_cache.tmp"
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"

echo "[" > "$OUTPUT_JSON"

# Cleanup
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth1 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | \
    tshark -l -r - -T json > "$TMP_NDP_JSON" &
    TCPDUMP_PID=$!
}

process_ndp() {
    echo "[*] Procesando tráfico NDP..."

    while true; do
        if [ -f "$TMP_NDP_JSON" ] && [ "$(wc -c < "$TMP_NDP_JSON")" -gt 100 ]; then
            cat "$TMP_NDP_JSON" | jq -c '.[]["_source"].layers' 2>/dev/null | \
            jq -c '{
                mac: .eth."eth.src",
                ipv6: (.icmpv6."icmpv6.nd.ns.target_address" // .icmpv6."icmpv6.nd.na.target_address")
            } | select(.mac != null and .ipv6 != null)' 2>/dev/null > "$NDP_CACHE"

            echo "[DEBUG] Tráfico NDP procesado:"
            cat "$NDP_CACHE"
        fi
        sleep 5
    done
}

get_mac_table() {
    echo "[*] Obteniendo tabla MAC desde gNMI..."

    gnmic -a srlswitch:57400 --skip-verify \
          -u admin -p "NokiaSrl1!" \
          -e json_ietf \
          get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" | \
      jq -c '.[0].updates[0].values."srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table".mac[]' 2>/dev/null | \
      grep -v "reserved" | \
      sed 's/ethernet-/e/; s/\//:/g' > "$TMP_MAC_JSON"
}

correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    timeout=30
    waited=0

    while [ ! -f "$NDP_CACHE" ] || [ ! -s "$NDP_CACHE" ]; do
        echo "[*] Esperando tráfico NDP para correlacionar..."
        sleep 5
        waited=$((waited + 5))
        if [ "$waited" -ge "$timeout" ]; then
            echo "[!] Timeout esperando tráfico NDP. Terminando correlación."
            return
        fi
    done

    cat "$TMP_MAC_JSON" | while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        if [ -n "$mac" ] && [ -n "$intf" ]; then
            ip6s=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | jq -r .ipv6)

            for ip6 in $ip6s; do
                if echo "$ip6" | grep -q "^fe80"; then
                    ip6_link="$ip6"
                else
                    ip6_global="$ip6"
                fi
            done

            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

            echo "{\"mac\": \"$mac\", \"interface\": \"$intf\", \"ipv6_link_local\": \"$ip6_link\", \"ipv6_global\": \"$ip6_global\", \"timestamp\": \"$timestamp\"}," >> "$OUTPUT_JSON"

            unset ip6_link ip6_global

            echo "[+] Correlación: $mac -> $intf"
        fi
    done
}

# Limpiar archivos temporales
rm -f "$NDP_CACHE" "$TMP_MAC_JSON" "$OUTPUT_JSON"

# Iniciar captura
start_ndp_capture
sleep 2

# Procesar tráfico en segundo plano
process_ndp &
PROCESS_PID=$!

# Obtener tabla MAC
while [ ! -s "$TMP_MAC_JSON" ]; do
    get_mac_table
    sleep 5
done

# Correlacionar
correlate_bindings

# Limpiar procesos
kill "$TCPDUMP_PID" >/dev/null 2>&1
kill "$PROCESS_PID" >/dev/null 2>&1

echo "[✓] Proceso finalizado. Salida: $OUTPUT_JSON"
