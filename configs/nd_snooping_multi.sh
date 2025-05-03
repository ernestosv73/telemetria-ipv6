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

    # Procesar archivos pcap con tshark para mejor análisis
    tshark -r "$FILE" -T fields -E separator=, -E quote=d \
        -e frame.time -e eth.src -e ipv6.src -e ipv6.dst -e icmpv6.type -e icmpv6.na.target -e icmpv6.ns.target_address \
        -e _ws.col.Info 2>/dev/null | while IFS=, read -r timestamp src_mac ipv6_src ipv6_dst icmp_type na_target ns_target info; do
        
        # Determinar tipo de mensaje y extraer información relevante
        case $icmp_type in
            135) # Neighbor Solicitation
                target="$ns_target"
                mac="$src_mac"
                ;;
            136) # Neighbor Advertisement
                target="$na_target"
                # En NA, la MAC está en una opción que no capturamos, usar src_mac (puede no ser fiable)
                mac="$src_mac"
                ;;
            *) continue ;;
        esac

        # Validar y limpiar datos
        mac=$(echo "$mac" | tr -d '"' | awk '{print tolower($0)}')
        target=$(echo "$target" | tr -d '"' | awk '{print tolower($0)}')

        # Solo procesar si tenemos ambos valores
        if [[ -n "$mac" && -n "$target" ]]; then
            echo "[+] Binding encontrado: $target -> $mac en $INTF"

            # Verificar si ya existe en el archivo
            EXISTS=$(jq --arg ip "$target" '.bindings[] | select(.ipv6 == $ip)' "$BINDING_FILE")
            
            if [ -z "$EXISTS" ]; then
                TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                jq --arg mac "$mac" --arg ip "$target" --arg intf "$INTF" --arg ts "$TIMESTAMP" \
                '.bindings += [{"mac": $mac, "ipv6": $ip, "interface": $intf, "timestamp": $ts}]' \
                "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"
            fi
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
