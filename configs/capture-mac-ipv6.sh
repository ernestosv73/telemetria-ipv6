#!/bin/sh

# Directorios necesarios
OUTPUT_DIR="/data"
mkdir -p $OUTPUT_DIR

# Archivos temporales
TMP_PCAP="/tmp/ndp_traffic.pcap"
TMP_NDP_JSON="/tmp/ipv6_ndp.json"
TMP_MAC_JSON="/tmp/mac_table.json"
OUTPUT_JSON="$OUTPUT_DIR/mac_ipv6_bindings.json"

# Inicializar archivo JSON final
echo "[" > "$OUTPUT_JSON"

# Función para limpiar al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico NDP a archivo pcap
capture_ndp_to_pcap() {
    echo "[*] Capturando tráfico NDP a archivo PCAP (espera 15s)..."
    timeout 15s tcpdump -i eth1 -w "$TMP_PCAP" 'icmp6 && (ip6[40] == 135 or ip6[40] == 136)' >/dev/null 2>&1
    echo "[*] Captura finalizada."
}

# Función para extraer MAC/IPv6 desde el PCAP
extract_mac_ipv6_bindings() {
    echo "[*] Extrayendo bindings MAC–IPv6 desde PCAP..."

    tshark -r "$TMP_PCAP" -T json | \
    jq -c '.[]["_source"].layers' | \
    jq -c '{
        mac: .eth."eth.src",
        ipv6: (.icmpv6."icmpv6.nd.ns.target_address" // .icmpv6."icmpv6.nd.na.target_address")
    } | select(.mac != null and .ipv6 != null)' \
    > "$TMP_NDP_JSON"
}

# Función para obtener tabla MAC desde gNMI
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

# Función para correlacionar MAC ↔ IPv6
correlate_bindings() {
    echo "[*] Correlacionando MACs aprendidas con IPv6..."

    cat "$TMP_MAC_JSON" | while IFS= read -r entry; do
        mac=$(echo "$entry" | jq -r '.address')
        intf=$(echo "$entry" | jq -r '.destination')

        if [ -n "$mac" ] && [ -n "$intf" ]; then
            ip6s=$(grep "\"mac\": \"$mac\"" "$TMP_NDP_JSON" | jq -r .ipv6)

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

# Limpiar archivos previos
rm -f "$TMP_PCAP" "$TMP_NDP_JSON" "$TMP_MAC_JSON" "$OUTPUT_JSON"

# Ejecutar pipeline
capture_ndp_to_pcap
extract_mac_ipv6_bindings
get_mac_table
correlate_bindings
