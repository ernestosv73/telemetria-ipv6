#!/bin/bash

INTERFACES=("e1-2" "e1-3")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$PCAP_FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
declare -A global_seen
declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    INTERFACE_BINDINGS["$IFACE"]="[]"

    if [ ! -f "$PCAP_FILE" ]; then
        echo "[!] No se encontró captura para $IFACE"
        continue
    fi

    # Extraemos campos clave con tshark (más robusto que tcpdump)
    while IFS=$'\t' read -r MAC IPV6; do
        [ -z "$MAC" ] || [ -z "$IPV6" ] && continue
        KEY="${MAC,,}-${IPV6,,}"
        if [[ -n "${global_seen[$KEY]}" ]]; then
            continue
        fi
        global_seen[$KEY]=1

        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        BINDING=$(jq -n \
                    --arg mac "$MAC" \
                    --arg ipv6 "$IPV6" \
                    --arg iface "$IFACE" \
                    --arg timestamp "$TIMESTAMP" \
                    '{mac: $mac, ipv6: $ipv6, interface: $iface, timestamp: $timestamp}')
        CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
        INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
        echo "[$IFACE] Binding encontrado: $IPV6 -> $MAC"
    done < <(tshark -r "$PCAP_FILE" -T fields \
        -e eth.src -e ipv6.src -Y 'icmpv6.type == 135 || icmpv6.type == 136' \
        2>/dev/null)
done

{
  echo "{"
  FIRST=1
  for IFACE in "${INTERFACES[@]}"; do
      [ "$FIRST" -eq 1 ] && FIRST=0 || echo ","
      echo -n "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}"
  done
  echo -e "\n}"
} > "$BINDING_FILE"

jq 'to_entries | map({key: .key, value: (.value | unique_by(.ipv6))}) | from_entries' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final generada en: $BINDING_FILE"
jq . "$BINDING_FILE"
