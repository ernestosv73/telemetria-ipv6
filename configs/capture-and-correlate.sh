#!/bin/bash

# === PARÁMETROS ===
INTERFACE="eth1"
DURATION=60
PCAP_FILE="/tmp/ndp_capture.pcap"
NDP_JSON="/tmp/ipv6_ndp.json"
MAC_TABLE_JSON="/tmp/mac_table.json"
OUTPUT_JSON="/data/mac_ipv6_bindings.json"
TMP_BULK="/tmp/es_data.tmp"
ES_URL="http://172.20.20.9:9200"
INDEX_NAME="mac-ipv6-$(date +"%Y.%m.%d")"
BULK_URL="$ES_URL/$INDEX_NAME/_bulk"

echo "⏳ Inicio de captura y correlación: $(date -u)"

# === CAPTURA ===
echo "[*] Capturando tráfico ICMPv6 por $DURATION segundos..."
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" -G "$DURATION" -W 1 \
  'icmp6 && (ip6[40] == 135 or ip6[40] == 136)' >/dev/null 2>&1

echo "[*] Convirtiendo captura a JSON..."
tshark -r "$PCAP_FILE" -T json > "$NDP_JSON"

# Validar si JSON está bien formado
if ! jq empty "$NDP_JSON" >/dev/null 2>&1; then
  echo "[!] JSON incompleto. Corrigiendo..."
  echo "]" >> "$NDP_JSON"
fi

# === OBTENER MAC TABLE ===
echo "[*] Obteniendo tabla MAC desde gNMI..."
gnmic -a srlswitch:57400 --skip-verify -u admin -p "NokiaSrl1!" -e json_ietf \
  get --path "/network-instance[name=lanswitch]/bridge-table/mac-table/mac" | \
  jq -c '.[0].updates[0].values."srl_nokia-network-instance:network-instance/bridge-table/srl_nokia-bridge-table-mac-table:mac-table".mac[]' \
  > "$MAC_TABLE_JSON"

# === CORRELACIÓN ===
echo "[*] Correlacionando datos..."
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

  timestamp=$(jq -r --arg mac "$mac" '
    .[]["_source"].layers as $l 
    | select($l.eth["eth.src"] != null and ($l.eth["eth.src"] | ascii_downcase) == $mac)
    | $l.frame["frame.time"]
    ' "$NDP_JSON" | head -n1)

  if [ -n "$ip6_link" ] || [ -n "$ip6_global" ]; then
    echo "  {" >> "$OUTPUT_JSON"
    echo "    \"mac\": \"$mac\"," >> "$OUTPUT_JSON"
    echo "    \"interface\": \"$intf\"," >> "$OUTPUT_JSON"
    [ -n "$ip6_link" ] && echo "    \"ipv6_link_local\": \"$ip6_link\"," >> "$OUTPUT_JSON"
    [ -n "$ip6_global" ] && echo "    \"ipv6_global\": \"$ip6_global\"," >> "$OUTPUT_JSON"
    echo "    \"timestamp\": \"${timestamp:-unknown}\"" >> "$OUTPUT_JSON"
    echo "  }," >> "$OUTPUT_JSON"
  fi
done

# Finalizar JSON correctamente
sed -i '$ s/},/}/' "$OUTPUT_JSON"
echo "]" >> "$OUTPUT_JSON"
echo "✅ Archivo generado: $OUTPUT_JSON"

# === ENVÍO A ELASTICSEARCH ===
echo "[*] Enviando a Elasticsearch..."

# Construir archivo de envío bulk
cat "$OUTPUT_JSON" | jq -c '.[]' | while read entry; do
    echo '{"index":{}}'
    echo "$entry"
done > "$TMP_BULK"

# Validar si hay datos para enviar
if [ ! -s "$TMP_BULK" ]; then
    echo "[!] No hay datos para enviar a Elasticsearch. Saltando..."
else
    curl -s -XPOST "$BULK_URL" \
         -H "Content-Type: application/json" \
         --data-binary @"$TMP_BULK" | jq '.'
    echo "[+] Datos enviados a $INDEX_NAME ✔"
fi

# Limpiar temporal
rm -f "$TMP_BULK"
