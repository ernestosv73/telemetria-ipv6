#!/bin/bash

# Interfaces a monitorear
INTERFACES=("e1-2" "e1-3" "e1-4" "e1-5")

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
    timeout 100 tcpdump -i "$IFACE" -vv ip6 and 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e > "$FILE" &  # ICMPv6 NS/NA
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

    # Extraer los datos de las direcciones MAC e IPv6 usando tcpdump
    tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e | while read -r line; do
        # Extraer la dirección MAC de la fuente
        if [[ "$line" =~ ([0-9a-f:]{17})\  >\ 33:33:ff:([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2}) ]]; then
            SRC_MAC="${BASH_REMATCH[1]}"
        fi

        # Extraer la dirección IPv6 de la solicitud de vecino o de la respuesta
        if [[ "$line" =~ ICMP6,\ neighbor\ solicitation,\ length ]]; then
            IPV6=$(echo "$line" | grep -oP 'who\ has\s+([0-9a-f:]+::[0-9a-f:]+)' | sed 's/who has //')
        elif [[ "$line" =~ ICMP6,\ neighbor\ advertisement,\ length ]]; then
            IPV6=$(echo "$line" | grep -oP 'target\s+([0-9a-f:]+::[0-9a-f:]+)' | sed 's/target //')
        fi

        # Si se encuentran ambos, agregar el binding
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

            # Limpiar variables para el siguiente ciclo
            SRC_MAC=""
            IPV6=""
        fi
    done
done

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"



        
