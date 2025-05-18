#!/bin/sh

# Crear directorios necesarios
mkdir -p /data /tmp

# Archivo de salida
OUTPUT_JSON="/data/mac_ipv6_bindings.json"

# Inicializar archivo JSON
echo "[" > $OUTPUT_JSON

# Función para limpiar y cerrar archivo JSON
cleanup_json() {
    # Elimina la última coma si existe
    if [ -f "$OUTPUT_JSON" ]; then
        sed -i '$ s/,$//' "$OUTPUT_JSON" 2>/dev/null || true
        echo "]" >> "$OUTPUT_JSON"
    fi
}
trap cleanup_json EXIT

# Función para capturar tráfico ICMPv6 (NS/NA)
start_ndp_capture() {
    echo "[*] Iniciando captura de tráfico ICMPv6..."
    tcpdump -i eth0 -U -w - 'icmp6 && ip6[40] == 135 or ip6[40] == 136' | tshark -l -r - -T json > /tmp/ipv6_ndp.json &
}

# Función para procesar NS/NA desde tshark
process_ndp() {
    while read line; do
        mac=$(echo "$line" | jq -r '.layers.eth | .eth_src_raw[0]' 2>/dev/null)
        ip6=$(echo "$line" | jq -r '.layers.ipv6 | .ipv6_src' 2>/dev/null)

        if [ "$mac" != "null" ] && [ "$ip6" != "null" ]; then
            entry="{\"mac\": \"$mac\", \"ipv6\": \"$ip6\", \"source\": \"NDP\", \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
            echo "$entry," >> $OUTPUT_JSON
            echo "[+] NDP: $mac -> $ip6"
        fi
    done < <(jq -c '.[]' /tmp/ipv6_ndp.json 2>/dev/null)
}

# Función para obtener tabla MAC desde gNMI
process_gnmic() {
    echo "[*] Iniciando suscripción a tabla MAC via gNMI..."
    gnmic --config /gnmic-config.yml subscribe | while read -r line; do
        # Extraer MAC e interfaz
        mac=$(echo "$line" | sed -n 's/.*"address": *"\([^"]*\)".*/\1/p')
        intf=$(echo "$line" | sed -n 's/.*"destination": *"\([^"]*\)".*/\1/p')

        if [ -n "$mac" ] && [ -n "$intf" ]; then
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            entry="{\"mac\": \"$mac\", \"interface\": \"$intf\", \"source\": \"bridge-table\", \"timestamp\": \"$timestamp\"}"
            echo "$entry," >> $OUTPUT_JSON
            echo "[+] BRIDGE TABLE: $mac -> $intf"
        fi
    done
}

# Iniciar componentes
start_ndp_capture
sleep 2

# Procesar eventos en paralelo
process_ndp &
process_gnmic

wait
