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
    if [ ! -f "$PCAP_FILE" ]; then
        echo "[!] No se encontró captura para la interfaz $IFACE"
        INTERFACE_BINDINGS["$IFACE"]="[]"
        continue
    fi

    INTERFACE_BINDINGS["$IFACE"]="[]"

    # Extraer MAC origen, dirección origen y dirección destino (target)
    while IFS=$'\t' read -r SRC_MAC SRC_IP TARGET_IPV6; do
        SRC_MAC=$(echo "$SRC_MAC" | tr '[:upper:]' '[:lower:]')
        SRC_IP=$(echo "$SRC_IP" | tr '[:upper:]' '[:lower:]')
        TARGET_IPV6=$(echo "$TARGET_IPV6" | tr '[:upper:]' '[:lower:]')

        for IPV6 in "$SRC_IP" "$TARGET_IPV6"; do
            # Validar dirección IPv6
            if [[ "$IPV6" =~ ^([0-9a-f:]+)$ && "$IPV6" != "::" ]]; then
                KEY="${SRC_MAC}-${IPV6}"
                if [[ -n "${global_seen[$KEY]}" ]]; then
                    continue
                fi
                global_seen[$KEY]=1

                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                BINDING=$(jq -n \
                            --arg mac "$SRC_MAC" \
                            --arg ipv6 "$IPV6" \
                            --arg iface "$IFACE" \
                            --arg timestamp "$TIMESTAMP" \
                            '{mac: $mac, ipv6: $ipv6, interface: $iface, timestamp: $timestamp}')
                CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
                INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
                echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
            fi
        done
    done < <(tshark -r "$PCAP_FILE" -T fields -e eth.src -e ipv6.src -e icmpv6.nd.target_address \
             -Y 'icmpv6.type == 135 || icmpv6.type == 136' 2>/dev/null)
done

# Generar JSON final
{
  echo "{"
  FIRST=1
  for IFACE in "${INTERFACES[@]}"; do
      if [ "$FIRST" -eq 1 ]; then
          FIRST=0
      else
          echo ","
      fi
      echo -n "  \"$IFACE\": ${INTERFACE_B_
