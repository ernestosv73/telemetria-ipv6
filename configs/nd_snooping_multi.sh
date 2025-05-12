#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
TMP_DIR="/tmp/nd_snoop"
BINDING_FILE="/root/bindings.json"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"
echo "[*] Capturando ND en ${INTERFACES[*]} por ${CAPTURE_DURATION}s..."
> "$BINDING_FILE"

# Lanzar capturas simultáneas
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" \
        -w "$TMP_DIR/$IFACE.pcap" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null &
    PIDS+=($!)
done
for PID in "${PIDS[@]}"; do wait "$PID"; done

echo "[*] Procesando paquetes..."

declare -A BINDINGS  # Clave: iface|ipv6 → valor: mac

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    tshark -r "$FILE" -Y 'icmpv6.type == 135 or icmpv6.type == 136' \
        -T fields -e eth.src -e ipv6.src 2>/dev/null | while IFS=$'\t' read -r MAC IPV6; do
        [[ -z "$MAC" || -z "$IPV6" ]] && continue
        MAC="${MAC,,}"  # Asegurar minúsculas
        IPV6="${IPV6,,}"
        KEY="${IFACE}|${IPV6}"
        BINDINGS["$KEY"]="$MAC"
    done
done

# Generar archivo JSON
echo '{ "bindings": [' > "$BINDING_FILE"
FIRST=1
for KEY in "${!BINDINGS[@]}"; do
    IFS='|' read -r IFACE IPV6 <<< "$KEY"
    MAC="${BINDINGS[$KEY]}"
    if [[ $FIRST -eq 0 ]]; then echo ',' >> "$BINDING_FILE"; fi
    echo "  { \"mac\": \"$MAC\", \"ipv6\": \"$IPV6\", \"interface\": \"$IFACE\" }" >> "$BINDING_FILE"
    FIRST=0
done
echo '] }' >> "$BINDING_FILE"

echo "[✓] Tabla de bindings generada en: $BINDING_FILE"
jq . "$BINDING_FILE"
