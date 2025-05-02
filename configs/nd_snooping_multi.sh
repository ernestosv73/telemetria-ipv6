#!/bin/bash

# Interfaces a monitorear
INTERFACES=("ethernet-1/2.0" "ethernet-1/3.0" "ethernet-1/4.0" "ethernet-1/5.0")

# Archivos
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
mkdir -p "$TMP_DIR"

# Crear estructura JSON si no existe
if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

# Iniciar capturas en paralelo
echo "[*] Capturando ND en interfaces durante 30 segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout 300 tcpdump -i "$IFACE" -vv ip6 and 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e > "$FILE" &
    PIDS+=($!)
done

# Esperar a que terminen todas las capturas
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

# Procesar cada archivo
echo "[*] Procesando paquetes ND..."
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"

    while read -r line; do
        if [[ "$line" =~ ^([0-9a-f:]{17})\ >\ ([0-9a-f:]{17}).* ]]; then
            SRC_MAC="${BASH_REMATCH[1]}"
        fi

        if [[ "$line" =~ ICMP6,\ neighbor\ (solicitation|advertisement).*\ who\ has\ ([0-9a-f:]+::[0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ICMP6,\ neighbor\ advertisement.*\ target\ ([0-9a-f:]+::[0-9a-f:]+) ]]; then
            IPV6="${BASH_REMATCH[1]}"
        fi

        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            # Verificar si ya existe
            EXISTS=$(jq --arg ip "$IPV6" '.bindings[] | select(.ipv6 == $ip)' "$BINDING_FILE")

            if [ -z "$EXISTS" ]; then
                echo "[+] Agregando binding: $IPV6 → $SRC_MAC en $INTF"
                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                jq --arg mac "$SRC_MAC" --arg ip "$IPV6" --arg intf "$INTF" --arg ts "$TIMESTAMP" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
            fi

            SRC_MAC=""
            IPV6=""
        fi
    done < "$FILE"
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
