#!/bin/sh

# Directorio de salida
OUTPUT_DIR="/data"
mkdir -p $OUTPUT_DIR

# Archivo de salida final
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"

# Archivos temporales
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"
NDP_CACHE="/tmp/ndp_cache.tmp"

# Inicializar archivo JSON final
echo "[" > "$OUTPUT_JSON"

# Función para limpiar y cerrar archivo JSON al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico ICMPv6 (NS/NA)
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth1 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | tshark -l -r - -T json > "$TMP_NDP_JSON" &
}

# Función para procesar NS/NA desde tshark
process_ndp() {
    echo "[*] Procesando tráfico NDP en tiempo real..."

    while read line; do
        mac=$(echo "$line" | jq -r '.layers.eth."eth.addr"' 2>/dev/null)
        ip6=$(echo "$line" | jq -r '.layers.ipv6."ipv6.addr"' 2>/dev/null)

        if [ "$mac" != "null" ] && [ "$ip6" != "null" ] && [ "$ip6" != "::" ]; then
            # Determinar si es link-local o global
            if echo "$ip6" | grep -q "^fe80"; then
                echo "{\"mac\": \"$mac\", \"ipv6_link_local\": \"$ip6\"}" >> "$NDP_CACHE"
            else
                echo "{\"mac\": \"$mac\", \"ipv6_global\": \"$ip6\"}" >> "$NDP_CACHE"
            fi
        fi
    done < <(jq -c '.[]' "$TMP_NDP_JSON" 2>/dev/null)
}

# Función para obtener tabla MAC desde gNMI
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

# Función para correlacionar MACs aprendidas con IPv6 desde NDP
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    cat "$TMP_MAC_JSON" | while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        # Esperar a que exista información en el caché
        while [ ! -f "$NDP_CACHE" ] || [ ! -s "$NDP_CACHE" ]; do
            echo "[*] Esperando tráfico NDP para correlacionar..."
            sleep 2
        done

        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        ip6_link=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep ipv6_link_local | tail -n1 | jq -r .ipv6_link_local)
        ip6_global=$(grep "\"mac\": \"$mac\"" "$NDP_CACHE" | grep ipv6_global | tail -n1 | jq -r .ipv6_global)

        if [ -n "$ip6_link" ]; then
            echo "[+] Correlación: $mac -> $ip6_link / $ip6_global"

            echo "{\"mac\": \"$mac\", \"interface\": \"$intf\", \"ipv6_link_local\": \"$ip6_link\"," > /tmp/json_entry.tmp
            if [ -n "$ip6_global" ]; then
                echo "\"ipv6_global\": \"$ip6_global\"," >> /tmp/json_entry.tmp
            else
                echo "" >> /tmp/json_entry.tmp
            fi
            echo "\"timestamp\": \"$timestamp\"}" >> /tmp/json_entry.tmp

            cat /tmp/json_entry.tmp | sed '/^"ipv6_global": ""$/d; s/,\s*"/"/' >> "$OUTPUT_JSON"
            echo "," >> "$OUTPUT_JSON"
        fi

        rm -f /tmp/json_entry.tmp
    done
}

# Limpiar archivos temporales anteriores
rm -f "$NDP_CACHE" "$TMP_MAC_JSON"

# Iniciar captura de tráfico
start_ndp_capture
sleep 2

# Lanzar procesamiento de NDP en segundo plano
process_ndp &

# Obtener tabla MAC
get_mac_table

# Esperar a tener datos de NDP
sleep 5

# Correlacionar MAC ↔ IPv6
correlate_bindings

# Eliminar última coma del JSON
sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
