#!/bin/bash

# Parámetros
INTERFACE="eth1"
NDP_JSON="/tmp/ipv6_ndp.json"
MAC_TABLE_JSON="/tmp/mac_table.json"
OUTPUT_JSON="/data/mac_ipv6_bindings.json"
KNOWN_MACS_FILE="/tmp/known_macs.txt"

# Directorio de salida
mkdir -p /data
echo "[" > "$OUTPUT_JSON"

# Función para limpiar al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico ICMPv6 en tiempo real
start_ndp_capture() {
    echo "[*] Iniciando captura en tiempo real de ICMPv6..."
    tcpdump -i "$INTERFACE" -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | \
        tshark -l -r - -T json > "$NDP_JSON" &
}

# Función para obtener tabla MAC desde el switch Nokia SR Linux
get_mac_table() {
    echo "[*] Obteniendo tabla MAC desde gNMI..."

    gnmic -a srlswitch:57400 --skip-verify \
          -u admin -p "NokiaSrl1!" -e json_ietf \
          get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" | \
      jq -c '.[0].updates[0].values."srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table".mac[]' | \
      grep -v "reserved" > "$MAC_TABLE_JSON"
}

# Función para correlacionar MAC ↔ IPv6 ↔ interfaz
correlate_bindings() {
    echo "[*] Correlacionando datos..."

    while true; do
        # Solo procesar si hay archivo JSON válido
        if [ -f "$NDP_JSON" ] && [ -s "$NDP_JSON" ]; then
            # Reinicializar caché de salida
            truncate -s 0 "$OUTPUT_JSON"
            echo "[" > "$OUTPUT_JSON"

            cat "$MAC_TABLE_JSON" | while read -r mac_entry; do
                mac=$(echo "$mac_entry" | jq -r '.address' | tr '[:upper:]' '[:lower:]')
                intf=$(echo "$mac_entry" | jq -r '.destination')

                ip6_link=$(jq -r --arg mac "$mac" '
                    .[]["_source"].layers as $l 
                    | select($l.eth["eth.src"] != null and ($l.eth["eth.src"] | ascii_downcase) == $mac)
                    | select($l.icmpv6["icmpv6.nd.ns.target_address"] | test("^fe80"))
                    | $l.icmpv6["icmpv6.nd.ns.target_address"]
                ' "$NDP_JSON" | head -n1)

                ip6_global=$(jq -r --arg mac "$mac" '
                    .[]["_source"].layers as $l 
                    | select($l.eth["eth.src"] != null and ($l.eth["eth.src"] | ascii_downcase) == $mac)
                    | select($l.icmpv6["icmpv6.nd.ns.target_address"] | test("^fe80") | not)
                    | $l.icmpv6["icmpv6.nd.ns.target_address"]
                ' "$NDP_JSON" | head -n1)

                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                if [ -n "$ip6_link" ] || [ -n "$ip6_global" ]; then
                    entry="{\"mac\": \"$mac\", \"interface\": \"$intf\""
                    [ -n "$ip6_link" ] && entry+=", \"ipv6_link_local\": \"$ip6_link\""
                    [ -n "$ip6_global" ] && entry+=", \"ipv6_global\": \"$ip6_global\""
                    entry+=", \"timestamp\": \"$timestamp\"}"
                    echo "$entry," >> "$OUTPUT_JSON"
                fi
            done

            # Limpiar archivo JSON
            sed -i '$ s/,$//' "$OUTPUT_JSON"
        else
            echo "[!] Aún no hay tráfico NDP para procesar."
        fi

        sleep 10
    done
}

# Limpiar archivos previos
rm -f "$NDP_JSON" "$MAC_TABLE_JSON" "$OUTPUT_JSON"
touch "$NDP_JSON" "$MAC_TABLE_JSON"

# Iniciar componentes
start_ndp_capture
sleep 2

# Obtener tabla MAC inicial
get_mac_table

# Lanzar correlación en bucle
correlate_bindings
