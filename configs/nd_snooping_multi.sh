#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal y archivo de salida
mkdir -p "$TMP_DIR"
echo '{}' > "$BINDING_FILE"  # Cambiamos a formato de salida deseado

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" \
        'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar que todos los procesos terminen
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

# Usaremos un array asociativo para agrupar por interfaz
declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue
    
    # Inicializar array para esta interfaz
    INTERFACE_BINDINGS["$IFACE"]="[]"
    
    while read -r line; do
        SRC_MAC=""
        SRC_IP=""
        TGT_IP=""
        TGT_MAC=""
        TYPE=""

        # Extraer MAC origen (formato más robusto)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"  # Convertir a minúsculas
        fi

        # Extraer IPv6 origen (mejorado)
        if [[ "$line" =~ ([0-9a-fA-F:]+)\.([0-9]+)[[:space:]]+> ]]; then
            SRC_IP="${BASH_REMATCH[1],,}"
        fi

        # Determinar tipo de mensaje y extraer información específica
        if [[ "$line" =~ "who has" ]]; then
            TYPE="NS"
            if [[ "$line" =~ who\ has\ ([0-9a-fA-F:]+) ]]; then
                TGT_IP="${BASH_REMATCH[1],,}"
            fi
            # Extraer MAC de target si está presente (para NS con SLLA)
            if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})[[:space:]]+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
                TGT_MAC="${BASH_REMATCH[3],,}"
            fi
        elif [[ "$line" =~ "tgt is" ]]; then
            TYPE="NA"
            if [[ "$line" =~ tgt\ is\ ([0-9a-fA-F:]+) ]]; then
                TGT_IP="${BASH_REMATCH[1],,}"
            fi
            # Extraer MAC de target (para NA)
            if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})[[:space:]]+([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
                TGT_MAC="${BASH_REMATCH[3],,}"
            fi
        fi

        # Registrar bindings encontrados
        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        
        # 1. Registrar MAC origen con IP origen (si es link-local)
        if [[ -n "$SRC_MAC" && -n "$SRC_IP" && "$SRC_IP" =~ ^fe80:: ]]; then
            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$SRC_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
            
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
        fi
        
        # 2. Registrar MAC origen con IP target (si es global)
        if [[ -n "$SRC_MAC" && -n "$TGT_IP" && ! "$TGT_IP" =~ ^fe80:: ]]; then
            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$TGT_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
            
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
        fi
        
        # 3. Registrar MAC target con IP target (si es diferente de MAC origen)
        if [[ -n "$TGT_MAC" && "$TGT_MAC" != "$SRC_MAC" && -n "$TGT_IP" ]]; then
            BINDING=$(jq -n \
                --arg mac "$TGT_MAC" \
                --arg ipv6 "$TGT_IP" \
                --arg interface "$IFACE" \
                --arg timestamp "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $interface, timestamp: $timestamp}')
            
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
        fi

    done < <(tcpdump -nn -r "$FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)
done

# Generar el archivo JSON final en el formato solicitado
echo "{" > "$BINDING_FILE"
FIRST=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST" -eq 1 ]; then
        FIRST=0
    else
        echo "," >> "$BINDING_FILE"
    fi
    
    echo -n "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}" >> "$BINDING_FILE"
done
echo -e "\n}" >> "$BINDING_FILE"

# Eliminar duplicados (por MAC, IPv6 e interfaz)
jq 'walk(if type == "array" then unique_by(.mac + .ipv6 + .interface) else . end)' "$BINDING_FILE" > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final en: $BINDING_FILE"
jq . "$BINDING_FILE"
