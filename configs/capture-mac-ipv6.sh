#!/bin/sh

# Directorios necesarios
OUTPUT_DIR="/data"
mkdir -p $OUTPUT_DIR

# Archivos temporales
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"
NDP_CACHE="/tmp/ndp_cache.tmp"

# Archivo de salida final
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"
echo "[" > "$OUTPUT_JSON"

# Función para limpiar JSON al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico ICMPv6
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth1 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | tshark -l -r - -T json > "$TMP_NDP_JSON" &
}

# Función para procesar tráfico NS/NA y guardar caché
process_ndp() {
    echo "[*] Procesando tráfico NDP..."

    while read line; do
        mac=$(echo "$line" | jq -r '..|.["eth.addr"]? // empty' 2>/dev/null)
        ip6=$(echo "$line" | jq -r '..|.["icmpv6.nd.ns.target_address"]? // empty' 2>/dev/null)

        if [ -n "$mac" ] && [ -n "$ip6" ]; then
            if echo "$ip6" | grep -q "^fe80"; then
                echo "{\"mac\": \"$mac\", \"ipv6_link_local\": \"$ip6\"}" >> "$NDP_CACHE"
            else
                echo "{\"mac\": \"$mac\", \"ipv6_global\": \"$ip6\"}" >> "$NDP_CACHE"
            fi
            echo "[+] NDP: $mac -> $ip6"
        fi
    done < <(jq -c '.[]' "$TMP_NDP_JSON" 2>/dev/null)
}

# Función para obtener tabla MAC via gNMI
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

# Función para correlacionar MACs aprendidas con IPv6
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    while [ ! -f "$NDP_CACHE" ] || [ ! -s "$NDP_CACHE" ]; do
        echo "[*] Esperando tráfico NDP para correlacionar..."
        sleep 2
    done

    cat "$TMP_MAC_JSON" | while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        # Buscar en caché
        ip6_link=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep ipv6_link_local | tail -n1 | jq -r .ipv6_link_local)
        ip6_global=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep ipv6_global | tail -n1 | jq -r .ipv6_global)

        if [ -n "$ip6_link" ] || [ -n "$ip6_global" ]; then
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            echo "[+] Correlación: $mac -> $ip6_link / $ip6_global"

            entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"timestamp\": \"$timestamp\""
            [ -n "$ip6_link" ] && entry+=", \"ipv6_link_local\": \"$ip6_link\""
            [ -n "$ip6_global" ] && entry+=", \"ipv6_global\": \"$ip6_global\""
            entry+="}"

            echo "$entry," >> "$OUTPUT_JSON"
        fi
    done
}

# Limpiar archivos previos
rm -f "$NDP_CACHE" "$TMP_MAC_JSON"

# Iniciar componentes
start_ndp_capture
sleep 2

# Lanzar procesamiento de NDP en segundo plano
process_ndp &

# Obtener tabla MAC
get_mac_table

# Esperar a tener datos de NDP
sleep 10

# Correlacionar MACs con IPv6
correlate_bindings
