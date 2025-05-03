#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
mkdir -p "$TMP_DIR"

if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[*] Capturando ND en interfaces durante 30 segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout 30 tcpdump -i "$IFACE" -vv -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"

    # Procesar con tcpdump en modo legible
    tcpdump -nn -v -r "$FILE" 2>/dev/null | while read -r line; do
        # Extraer MAC origen
        if [[ "$line" =~ ([0-9a-fA-F:]{17})\ > ]]; then
            mac="${BASH_REMATCH[1]}"
        fi

        # Extraer IPv6 según tipo de mensaje
        if [[ "$line" =~ "ICMP6, neighbor solicitation" ]]; then
            if [[ "$line" =~ "who has ([0-9a-fA-F:]+)" ]]; then
                ipv6="${BASH_REMATCH[1]}"
            fi
        elif [[ "$line" =~ "ICMP6, neighbor advertisement" ]]; then
            if [[ "$line" =~ "tgt is ([0-9a-fA-F:]+)" ]]; then
                ipv6="${BASH_REMATCH[1]}"
            fi
        fi

        # Si tenemos ambos valores, procesar
        if [[ -n "$mac" && -n "$ipv6" ]]; then
            echo "[+] Binding encontrado: $ipv6 -> $mac en $INTF"
            
            # Convertir a formato estándar
            mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
            ipv6=$(echo "$ipv6" | tr '[:upper:]' '[:lower:]')

            # Verificar si ya existe
            EXISTS=$(jq --arg ip "$ipv6" '.bindings[] | select(.ipv6 == $ip)' "$BINDING_FILE")
            
            if [ -z "$EXISTS" ]; then
                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                jq --arg mac "$mac" --arg ip "$ipv6" --arg intf "$INTF" --arg ts "$TIMESTAMP" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
            fi

            # Resetear variables para el próximo paquete
            mac=""
            ipv6=""
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
