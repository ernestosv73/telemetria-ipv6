#!/bin/sh

# Directorio de salida
OUTPUT_DIR="/data"
mkdir -p $OUTPUT_DIR

# Archivo de salida
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"

# Archivos temporales
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"

# Inicializar archivo JSON final
echo "[" > "$OUTPUT_JSON"

# Función para limpiar al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico ICMPv6
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth0 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | tshark -l -r - -T json > "$TMP_NDP_JSON" &
}

# Función para procesar tráfico ICMPv6 y guardar en caché temporal
process_ndp() {
    echo "[*] Procesando tráfico NDP..."

    while read line; do
        mac=$(echo "$line" | jq -r '.layers.eth."eth.addr"' 2>/dev/null)
        ip6=$(echo "$line" | jq -r '.layers.ipv6."ipv6.addr"' 2>/dev/null)

        if [ "$mac" != "null" ] && [ "$ip6" != "null" ] && [ "$ip6" != "::" ]; then
            # Si es link-local
            if echo "$ip6" | grep -q "^fe80"; then
                echo "{\"mac\": \"$mac\", \"ipv6_link_local\": \"$ip6\"}" >> /tmp/ndp_cache.tmp
            else
                echo "{\"mac\": \"$mac\", \"ipv6_global\": \"$ip6\"}" >> /tmp/ndp_cache.tmp
            fi
        fi
    done < <(jq -c '.[]' "$TMP_NDP_JSON" 2>/dev/null)
}

# Función para obtener tabla MAC via gnmic
get_mac_table() {
    echo "[*] Obteniendo tabla MAC desde gNMI..."

    gnmic -a srlswitch:57400 --skip-verify \
          -u admin -p "NokiaSrl1!" \
          -e json_ietf \
          get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" | \
      jq -c '.[0].updates[0].values."srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table".mac[]' | \
      grep -v "reserved" | \
      sed 's/ethernet-/e/; s/\//:/g' > "$TMP_MAC_JSON"
}

# Función para correlacionar MACs con IPv6 desde el caché
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    cat "$TMP_MAC_JSON" | while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        if [ -n "$mac" ] && [ -n "$intf" ]; then
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            ip6_link=$(grep "\"mac\": \"$mac\"" /tmp/ndp_cache.tmp | grep ipv6_link_local | jq -r .ipv6_link_local)
            ip6_global=$(grep "\"mac\": \"$mac\"" /tmp/ndp_cache.tmp | grep ipv6_global | jq -r .ipv6_global)

            # Construir entrada JSON
            entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"source\": \"bridge-table\", \"timestamp\": \"$timestamp\""
            [ -n "$ip6_link" ] && entry+=", \"ipv6_link_local\": \"$ip6_link\""
            [ -n "$ip6_global" ] && entry+=", \"ipv6_global\": \"$ip6_global\""
            entry+="}"

            echo "$entry," >> "$OUTPUT_JSON"
            echo "[+] Correlación: $mac -> $ip6_link / $ip6_global"
        fi
    done
}

# Iniciar componentes
rm -f /tmp/ndp_cache.tmp /tmp/mac_table.json

start_ndp_capture
sleep 2

# Lanzar procesamiento en segundo plano
process_ndp &
get_mac_table
correlate_bindings
