#!/bin/bash

# Parámetros
JSON_FILE="/data/mac_ipv6_bindings.json"
ES_URL="http://172.20.20.9:9200"
INDEX_NAME="mac-ipv6-$(date +"%Y.%m.%d")"
BULK_URL="$ES_URL/$INDEX_NAME/_bulk"

echo "[*] Verificando archivo $JSON_FILE..."
if [ ! -f "$JSON_FILE" ]; then
    echo "[!] Archivo no encontrado: $JSON_FILE"
    exit 1
fi

echo "[*] Enviando datos a Elasticsearch..."

# Preparar datos para envío bulk
cat "$JSON_FILE" | jq -c '.[]' | while read entry; do
    echo '{"index":{}}'
    echo "$entry"
done > /tmp/es_data.tmp

# Enviar datos a Elasticsearch
curl -s -XPOST "$BULK_URL" \
     -H "Content-Type: application/json" \
     --data-binary @/tmp/es_data.tmp | jq .

echo ""
echo "[+] Datos enviados al índice '$INDEX_NAME'"
