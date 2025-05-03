#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
mkdir -p "$TMP_DIR"

if [ ! -f "$BINDING_FILE" ]; then
    echo '{"bindings": []}' > "$BINDING_FILE"
fi

echo "[*] Capturando ND en interfaces durante 60 segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout 60 tcpdump -i "$IFACE" -vv -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    INTF="$IFACE"
    
    # Extraer información completa con tcpdump
    tcpdump -nn -v -e -r "$FILE" 2>/dev/null | while read -r line; do
        mac=""
        ipv6=""
        
        # Extraer MAC origen (formato tcpdump con -e)
        if [[ "$line" =~ ([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}).* > ]]; then
            mac="${BASH_REMATCH[1]}"
        fi

        # Extraer IPv6 para Neighbor Solicitation
        if [[ "$line" =~ "ICMP6, neighbor solicitation" && "$line" =~ "who has ([0-9a-fA-F:]+)" ]]; then
            ipv6="${BASH_REMATCH[1]}"
            echo "DEBUG [NS]: MAC=$mac -> IPv6=$ipv6" >&2
        fi

        # Extraer IPv6 para Neighbor Advertisement
        if [[ "$line" =~ "ICMP6, neighbor advertisement" && "$line" =~ "tgt is ([0-9a-fA-F:]+)" ]]; then
            ipv6="${BASH_REMATCH[1]}"
            # Extraer MAC de la opción link-layer
            if [[ "$line" =~ "([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})" ]]; then
                mac="${BASH_REMATCH[1]}"
            fi
            echo "DEBUG [NA]: MAC=$mac -> IPv6=$ipv6" >&2
        fi

        # Solo procesar si tenemos ambos valores
        if [[ -n "$mac" && -n "$ipv6" ]]; then
            echo "[+] Binding encontrado: $ipv6 -> $mac en $INTF"
            
            # Normalizar formato
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
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
