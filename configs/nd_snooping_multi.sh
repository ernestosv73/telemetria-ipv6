#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
BINDING_FILE="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
CAPTURE_DURATION=30

mkdir -p "$TMP_DIR"

# Inicializar archivo JSON vacío
echo '{}' > "$BINDING_FILE"

echo "[*] Capturando mensajes ND (NS/NA) durante ${CAPTURE_DURATION} segundos..."
PIDS=()
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    timeout "$CAPTURE_DURATION" tcpdump -i "$IFACE" -w "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' &
    PIDS+=($!)
done

# Esperar todas las capturas
for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null
done

echo "[*] Procesando paquetes ND..."

# Arreglo asociativo para almacenar bindings por interfaz
declare -A BINDINGS_BY_INTERFACE
for IFACE in "${INTERFACES[@]}"; do
    BINDINGS_BY_INTERFACE["$IFACE"]="[]"
done

# Arreglo global para evitar duplicados
declare -A SEEN_GLOBAL

# Procesar cada interfaz y acumular bindings
for IFACE in "${INTERFACES[@]}"; do
    FILE="$TMP_DIR/$IFACE.pcap"
    [ -f "$FILE" ] || continue

    echo "[+] Procesando paquetes en $IFACE..."

    while read -r line; do
        SRC_MAC=""
        IPV6=""

        # Extraer dirección MAC
        if [[ "$line" =~ ([0-9a-fA-F:]{17}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer dirección IPv6 (global o link-local)
        if [[ "$line" =~ (who has|tgt is)[[:space:]]+([0-9a-fA-F:\.\%]+) ]]; then
            IPV6="${BASH_REMATCH[2],,}"
        fi

        # Registrar solo si ambos campos están presentes
        if [[ -n "$SRC_MAC" && -n "$IPV6" ]]; then
            KEY="${SRC_MAC}-${IPV6}"
            if [[ -n "${SEEN_GLOBAL[$KEY]}" ]]; then
                continue
            fi
            SEEN_GLOBAL[$KEY]=1

            TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

            BINDING=$(jq -n \
                --arg mac "$SRC_MAC" \
                --arg ipv6 "$IPV6" \
                --arg intf "$IFACE" \
                --arg ts "$TIMESTAMP" \
                '{mac: $mac, ipv6: $ipv6, interface: $intf, timestamp: $ts}')

            # Agregar binding a la interfaz correspondiente
            CURRENT="${BINDINGS_BY_INTERFACE[$IFACE]}"
            NEW_BINDING=$(echo "$CURRENT" | jq --argjson binding "$BINDING" '. + [$binding]')
            BINDINGS_BY_INTERFACE["$IFACE"]="$NEW_BINDING"
        fi
    done < <(tcpdump -nn -r "$FILE" 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' -e 2>/dev/null)
done

# Generar archivo JSON final
FINAL_JSON="{"
FIRST=1
for IFACE in "${INTERFACES[@]}"; do
    if [ "$FIRST" -eq 1 ]; then
        FINAL_JSON+="\"$IFACE\": ${BINDINGS_BY_INTERFACE[$IFACE]}"
        FIRST=0
    else
        FINAL_JSON+=",\"$IFACE\": ${BINDINGS_BY_INTERFACE[$IFACE]}"
    fi
done
FINAL_JSON+="}"

# Eliminar duplicados por IPv6 en cada interfaz
echo "$FINAL_JSON" | jq 'with_entries(.value |= unique_by(.ipv6))' > "$BINDING_FILE"

# Mostrar resultado
echo "[✓] Tabla final generada en: $BINDING_FILE"
cat "$BINDING_FILE"
