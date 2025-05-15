#!/bin/bash

# Configuración inicial
INTERFACES=("e1-2" "e1-3" "e1-4")
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
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' >/dev/null 2>&1 &
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

    if [ ! -s "$PCAP_FILE" ]; then
        echo "[!] No hay datos para $IFACE"
        continue
    fi

    while IFS=$'\t' read -r MAC SRCIP TARGET; do
        MAC="${MAC,,}"
        SRCIP="${SRCIP,,}"
        TARGET="${TARGET,,}"

        # Usar dirección más útil (TARGET para NA, SRCIP para NS)
        IPV6="$SRCIP"
        [[ "$TARGET" != "" && "$TARGET" != "::" ]] && IPV6="$TARGET"

        # Validar
        if [[ "$MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ && "$IPV6" =~ : ]]; then
            KEY="${MAC}-${IPV6}"
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
        fi
    done < <(tshark -r "$PCAP_FILE" -T fields -e eth.src -e ipv6.src -e icmpv6.nd.target_address \
             -Y 'icmpv6.type == 135 || icmpv6.type == 136' 2>/dev/null)
done

# Crear JSON final
{
  echo "{"
  FIRST=1
  for IFACE in "${INTERFACES[@]}"; do
      if [ "$FIRST" -eq 1 ]; then
          FIRST=0
      else
          echo ","
      fi
      echo -n "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}"
  done
  echo -e "\n}"
} > "$BINDING_FILE"

# Deduplicar por IPv6 final
jq 'to_entries | map({key: .key, value: (.value | unique_by(.ipv6))}) | from_entries' "$BINDING_FILE" \
    > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final generada en: $BINDING_FILE"
jq . "$BINDING_FILE"
