#!/bin/bash

# Parámetros
INTERFACE="eth1"
NDP_JSON="/tmp/ipv6_ndp.json"
MAC_TABLE_JSON="/tmp/mac_table.json"
OUTPUT_JSON="/data/mac_ipv6_bindings.json"
KNOWN_MACS_FILE="/tmp/known_macs.txt"

# Inicializar directorios
mkdir -p /data /tmp
truncate -s 0 "$NDP_JSON"
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

# Función para obtener tabla MAC desde gNMI
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

    # Cargar MACs conocidas del switch
    while true; do
        if [ ! -f "$MAC_TABLE_JSON" ] || [ ! -s "$MAC_TABLE_JSON" ]; then
            echo "[!] Tabla MAC vacía o no disponible. Reintentando..."
            get_mac_table
            sleep 5
            continue
        fi

        # Procesar solo nuevas líneas del archivo NDP
        tail -n +$(( $(wc -l < "$NDP_JSON") - 1 )) "$NDP_JSON" 2>/dev/null | \
        while IFS= read -r line; do
            if echo "$line" | jq empty >/dev/null 2>&1; then
                mac=$(echo "$line" | jq -r '..|.eth.src // empty' | tr '[:upper:]' '[:lower:]')
                ip6=$(echo "$line" | jq -r '..|.nd.target_address // empty')

                if [ -n "$mac" ] && [ -n "$ip6" ]; then
                    intf=$(grep "\"address\": \"$mac\"" "$MAC_TABLE_JSON" | jq -r '.destination' | head -n1)

                    type="global"
                    echo "$ip6" | grep -q "^fe80" && type="link_local"

                    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

                    entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"ipv6_$type\": \"$ip6\", \"timestamp\": \"$timestamp\"}"
                    echo "$entry" | jq empty >/dev/null 2>&1 && echo "$entry," >> "$OUTPUT_JSON"
                fi
            fi
        done

        sleep 5
    done
}

# Limpiar archivos previos
rm -f "$NDP_JSON" "$OUTPUT_JSON"
touch "$NDP_JSON"
echo "[" > "$OUTPUT_JSON"

# Iniciar componentes
start_ndp_capture
sleep 2

# Obtener tabla MAC inicial
get_mac_table

# Lanzar correlación en bucle
correlate_bindings
