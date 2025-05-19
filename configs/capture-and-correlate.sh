#!/bin/bash

# Parámetros
INTERFACE="eth1"
NDP_JSON_TMP="/tmp/ipv6_ndp.tmp.json"
MAC_TABLE_JSON="/tmp/mac_table.json"
OUTPUT_JSON="/data/mac_ipv6_bindings.json"

# Directorio de salida
mkdir -p /data
echo "[" > "$OUTPUT_JSON"

# Función para limpiar JSON al finalizar
cleanup_json() {
    sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
    echo "]" >> "$OUTPUT_JSON"
}
trap cleanup_json EXIT

# Función para capturar tráfico NDP en tiempo real
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6 en $INTERFACE..."
    tshark -i "$INTERFACE" -T json 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | \
        grep -v '^$$' > "$NDP_JSON_TMP" &
}

# Función para obtener tabla MAC desde gNMI
get_mac_table() {
    echo "[*] Obteniendo tabla MAC desde gNMI..."
    gnmic -a srlswitch:57400 --skip-verify \
          -u admin -p "NokiaSrl1!" -e json_ietf \
          get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" | \
      jq -c '.[0].updates[0].values."srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table".mac[]' \
      > "$MAC_TABLE_JSON"
}

# Función para procesar y correlacionar datos
correlate_bindings() {
    echo "[*] Correlacionando MAC ↔ IPv6 ↔ interfaz..."

    # Cargar lista de MACs conocidas
    known_macs=$(mktemp)
    cat "$MAC_TABLE_JSON" | jq -r '.address' | tr '[:upper:]' '[:lower:]' > "$known_macs"

    while true; do
        if [ ! -s "$NDP_JSON_TMP" ]; then
            sleep 2
            continue
        fi

        # Procesar cada línea nueva del archivo temporal
        tail -n +$(cat "$NDP_JSON_TMP" | wc -l) "$NDP_JSON_TMP" | while read -r line; do
            mac=$(echo "$line" | jq -r '..|.eth.src // empty' | tr '[:upper:]' '[:lower:]')
            ip6=$(echo "$line" | jq -r '..|.nd.target_address // empty')

            if [ -n "$mac" ] && [ -n "$ip6" ]; then
                intf=$(grep "\"$mac\"" "$MAC_TABLE_JSON" | jq -r '.destination' | head -n1)

                if [ -n "$intf" ]; then
                    type="global"
                    echo "$ip6" | grep -q "^fe80" && type="link_local"

                    entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"ipv6_$type\": \"$ip6\", \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
                    echo "$entry," >> "$OUTPUT_JSON"
                    echo "$entry"
                fi
            fi
        done

        sleep 5
    done
}

# Limpiar archivos anteriores
rm -f "$NDP_JSON_TMP" "$OUTPUT_JSON"
touch "$NDP_JSON_TMP"
echo "[" > "$OUTPUT_JSON"

# Iniciar componentes
start_ndp_capture
sleep 2

# Lanzar correlación en bucle
correlate_bindings
