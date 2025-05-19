#!/bin/sh

# Directorios necesarios
OUTPUT_DIR="/data"
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
NDP_CACHE="/tmp/ndp_cache.tmp"
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"

mkdir -p $OUTPUT_DIR /tmp

# Función para limpiar JSON al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Iniciar captura de tráfico ICMPv6
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth1 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | tshark -l -r - -T json > "$TMP_NDP_JSON" &
}

# Procesar tráfico NDP y guardar en caché temporal
process_ndp() {
    echo "[*] Procesando tráfico NDP..."

    while true; do
        cat "$TMP_NDP_JSON" | jq -c '.[]["_source"].layers' 2>/dev/null | jq -c '{
            mac: .eth."eth.src",
            ipv6: (.icmpv6."icmpv6.nd.ns.target_address" // .icmpv6."icmpv6.nd.na.target_address")
        } | select(.mac != null and .ipv6 != null)' > "$NDP_CACHE"

        sleep 5
    done
}

# Obtener tabla MAC desde el switch Nokia SR Linux
get_mac_table() {
    echo "[*] Obteniendo tabla MAC desde gNMI..."

    response=$(mktemp)
    gnmic -a srlswitch:57400 --skip-verify \
          -u admin -p "NokiaSrl1!" \
          get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" > "$response"

    # Extraer MACs aprendidas
    cat "$response" | jq -c '..|.address? // empty' > /tmp/mac_list.tmp
    cat "$response" | jq -c '..|.destination? // empty' > /tmp/intf_list.tmp
}

# Correlacionar MAC ↔ IPv6 aprendidas
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    while [ ! -f "$NDP_CACHE" ] || [ ! -s "$NDP_CACHE" ]; do
        echo "[*] Esperando tráfico NDP para correlacionar..."
        sleep 5
    done

    paste /tmp/mac_list.tmp /tmp/intf_list.tmp | while read -r mac intf; do
        if [ -n "$mac" ] && [ -n "$intf" ]; then
            ip6_link=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep -i 'fe80' | jq -r .ipv6)
            ip6_global=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep -v 'fe80' | jq -r .ipv6)

            if [ -n "$ip6_link" ] || [ -n "$ip6_global" ]; then
                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                entry="{\"mac\": \"$mac\", \"interface\": \"$intf\""
                [ -n "$ip6_link" ] && entry+=", \"ipv6_link_local\": \"$ip6_link\""
                [ -n "$ip6_global" ] && entry+=", \"ipv6_global\": \"$ip6_global\""
                entry+="}"

                echo "$entry," >> "$OUTPUT_JSON"
                echo "[+] Correlación: $mac -> $ip6_link / $ip6_global"
            fi
        fi
    done
}

# Limpiar archivos previos
rm -f "$NDP_CACHE" "$TMP_NDP_JSON" "$OUTPUT_JSON"
echo "[" > "$OUTPUT_JSON"

# Iniciar componentes
start_ndp_capture
sleep 2

# Lanzar procesamiento en segundo plano
process_ndp &

# Recuperar tabla MAC cada 30 segundos
while true; do
    get_mac_table
    correlate_bindings
    sleep 30
done
