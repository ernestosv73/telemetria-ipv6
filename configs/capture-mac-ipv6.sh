#!/bin/sh

# Directorio de salida
OUTPUT_DIR="/data"
mkdir -p $OUTPUT_DIR

# Archivos
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"
TMP_CACHE="/tmp/ndp_cache.tmp"

# Inicializar salida
echo "[" > "$OUTPUT_JSON"

# Limpieza final
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Captura NDP
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth1 -U -w - 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' | \
        tshark -l -r - -T json > "$TMP_NDP_JSON" &
}

# Procesa JSON generado por tshark
process_ndp() {
    echo "[*] Procesando tráfico NDP..."
    > "$TMP_CACHE"

    jq -c '.[]' "$TMP_NDP_JSON" 2>/dev/null | while read -r line; do
        mac=$(echo "$line" | jq -r '.layers.eth."eth.addr"' 2>/dev/null)
        ip6=$(echo "$line" | jq -r '.layers.ipv6."ipv6.addr"' 2>/dev/null)

        if [ "$mac" != "null" ] && [ "$ip6" != "null" ] && [ "$ip6" != "::" ]; then
            if echo "$ip6" | grep -q "^fe80"; then
                echo "{\"mac\": \"$mac\", \"ipv6_link_local\": \"$ip6\"}" >> "$TMP_CACHE"
            else
                echo "{\"mac\": \"$mac\", \"ipv6_global\": \"$ip6\"}" >> "$TMP_CACHE"
            fi
        fi
    done
}

# Obtiene la tabla MAC del switch
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

# Correlación entre MAC aprendidas y NDP
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    if [ ! -f "$TMP_CACHE" ]; then
        echo "[-] No se encontró $TMP_CACHE. ¿Falló el procesamiento NDP?"
        return
    fi

    while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        if [ -n "$mac" ] && [ -n "$intf" ]; then
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            ip6_link=$(grep "\"mac\": \"$mac\"" "$TMP_CACHE" | grep ipv6_link_local | jq -r .ipv6_link_local)
            ip6_global=$(grep "\"mac\": \"$mac\"" "$TMP_CACHE" | grep ipv6_global | jq -r .ipv6_global)

            entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"source\": \"bridge-table\", \"timestamp\": \"$timestamp\""
            [ -n "$ip6_link" ] && entry+=", \"ipv6_link_local\": \"$ip6_link\""
            [ -n "$ip6_global" ] && entry+=", \"ipv6_global\": \"$ip6_global\""
            entry+="}"

            echo "$entry," >> "$OUTPUT_JSON"
            echo "[+] Correlación: $mac -> $ip6_link / $ip6_global"
        fi
    done < "$TMP_MAC_JSON"
}

# Limpiar previos
rm -f "$TMP_CACHE" "$TMP_MAC_JSON"

# Flujo principal
start_ndp_capture
sleep 2  # tiempo para capturar algunos paquetes

process_ndp  # ahora en primer plano
get_mac_table
correlate_bindings
