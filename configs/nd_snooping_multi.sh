#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")  # Interfaces que deseas espiar
TMP_DIR="/tmp/nd_snoop"
mkdir -p "$TMP_DIR"
BINDING_FILE="$TMP_DIR/bindings.json"
> "$BINDING_FILE"

echo '[*] Capturando mensajes ND (NS y NA)...'
for IFACE in "${INTERFACES[@]}"; do
    tcpdump -i "$IFACE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -w "$TMP_DIR/$IFACE.pcap" -c 50 &
done

wait
echo "[*] Procesando paquetes capturados..."

declare -A CURRENT_BINDINGS  # llave: iface|ipv6  → valor: mac

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    if [[ ! -f "$FILE" ]]; then continue; fi

    tshark -r "$FILE" -Y 'icmpv6.type == 135 or icmpv6.type == 136' \
        -T fields -e eth.src -e ipv6.src | while IFS=$'\t' read -r SRC_MAC IPV6; do
        [[ -z "$SRC_MAC" || -z "$IPV6" ]] && continue

        KEY="${IFACE}|${IPV6}"
        CURRENT_BINDINGS["$KEY"]="$SRC_MAC"
    done
done

# Crear nuevo archivo JSON con los bindings actuales
echo '{ "bindings": [' > "$BINDING_FILE"
FIRST=1
for KEY in "${!CURRENT_BINDINGS[@]}"; do
    IFS='|' read -r IFACE IPV6 <<< "$KEY"
    MAC="${CURRENT_BINDINGS[$KEY]}"

    if [ $FIRST -eq 0 ]; then echo ',' >> "$BINDING_FILE"; fi
    echo "  { \"mac\": \"$MAC\", \"ipv6\": \"$IPV6\", \"interface\": \"$IFACE\" }" >> "$BINDING_FILE"
    FIRST=0
done
echo ']}' >> "$BINDING_FILE"

echo "[✓] Bindings generados:"
cat "$BINDING_FILE"
