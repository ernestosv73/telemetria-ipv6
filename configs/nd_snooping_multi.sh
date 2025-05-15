#!/bin/bash

# Configuración inicial
INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

# Crear directorio temporal y archivo de salida
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

# Esperar a que todas las capturas finalicen
for PID in "${PIDS[@]}"; do
    wait "$PID"
done

echo "[*] Procesando paquetes ND..."

# Declaramos un arreglo asociativo para almacenar los bindings de cada interfaz
declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    if [ ! -f "$PCAP_FILE" ]; then
        echo "[!] No se encontró captura para la interfaz $IFACE"
        INTERFACE_BINDINGS["$IFACE"]="[]"
        continue
    fi

    # Inicializamos el array JSON y el hash para detectar duplicados por IPv6 en la interfaz
    INTERFACE_BINDINGS["$IFACE"]="[]"
    declare -A seen

    # Procesamos la captura con tcpdump
    while IFS= read -r line; do
        SRC_MAC=""
        IPV6=""
        # Extraer la MAC de origen (link-layer)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Distinguir entre mensajes NS y NA para extraer la IPv6 objetivo
        if [[ "$line" =~ who[[:space:]]+has[[:space:]]+([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        elif [[ "$line" =~ tgt[[:space:]]+is[[:space:]]+([0-9a-fA-F:]+) ]]; then
            IPV6="${BASH_REMATCH[1],,}"
        fi

        # Registrar binding solo si se extrajeron ambos valores y no se ha incluido ya esta IPv6
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            if [[ -n "${seen[$IPV6]}" ]]; then
                continue
            fi
            seen["$IPV6"]=1
            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            BINDING=$(jq -n \
                        --arg mac "$SRC_MAC" \
                        --arg ipv6 "$IPV6" \
                        --arg iface "$IFACE" \
                        --arg timestamp "$TIMESTAMP" \
                        '{mac: $mac, ipv6: $ipv6, interface: $iface, timestamp: $timestamp}')
            # Actualizar el array JSON de la interfaz
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
            echo "[$IFACE] Binding encontrado: $IPV6 -> $SRC_MAC"
        fi
    done < <(tcpdump -nn -r "$PCAP_FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)

    # Limpiar la variable 'seen' para la siguiente interfaz
    unset seen
done

# Construir el archivo JSON final
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

# Aplicar deduplicación por interfaz con jq (por seguridad)
jq 'to_entries | map({key: .key, value: (.value | unique_by(.ipv6))}) | from_entries' "$BINDING_FILE" \
    > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final generada en: $BINDING_FILE"
jq . "$BINDING_FILE"
