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

# Declaramos un arreglo asociativo para almacenar los bindings por interfaz
declare -A INTERFACE_BINDINGS

for IFACE in "${INTERFACES[@]}"; do
    PCAP_FILE="$TMP_DIR/$IFACE.pcap"
    if [ ! -f "$PCAP_FILE" ]; then
        echo "[!] No se encontró captura para la interfaz $IFACE"
        INTERFACE_BINDINGS["$IFACE"]="[]"
        continue
    fi

    # Inicializamos el array JSON para la interfaz y un arreglo de deduplicación local
    INTERFACE_BINDINGS["$IFACE"]="[]"
    declare -A seen

    # Se utiliza -vv para obtener mayor detalle en la salida
    while IFS= read -r line; do
        SRC_MAC=""
        SRC_IP=""
        TARGET_IP=""

        # Extraer la dirección MAC origen (la primera MAC suele ser la del origen)
        if [[ "$line" =~ ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}) ]]; then
            SRC_MAC="${BASH_REMATCH[1],,}"
        fi

        # Extraer la dirección IPv6 de origen desde el encabezado (pattern: "IP6 <src> >")
        if [[ "$line" =~ IP6[[:space:]]+([0-9a-fA-F:]+)[[:space:]]+\> ]]; then
            SRC_IP="${BASH_REMATCH[1],,}"
        fi

        # Extraer la dirección objetivo mediante los patrones ND:
        # Para Neighbor Solicitation (NS) se busca "who has"
        if [[ "$line" =~ who[[:space:]]+has[[:space:]]+([0-9a-fA-F:]+) ]]; then
            TARGET_IP="${BASH_REMATCH[1],,}"
        # Para Neighbor Advertisement (NA) se busca "tgt is"
        elif [[ "$line" =~ tgt[[:space:]]+is[[:space:]]+([0-9a-fA-F:]+) ]]; then
            TARGET_IP="${BASH_REMATCH[1],,}"
        fi

        TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

        # Función para registrar un binding en la interfaz actual, evitando duplicados
        add_binding() {
            local ip="$1"
            if [[ -z "$ip" || -z "$SRC_MAC" ]]; then
                return
            fi
            if [[ -n "${seen[$ip]}" ]]; then
                return
            fi
            seen["$ip"]=1
            BINDING=$(jq -n \
                        --arg mac "$SRC_MAC" \
                        --arg ipv6 "$ip" \
                        --arg iface "$IFACE" \
                        --arg timestamp "$TIMESTAMP" \
                        '{mac: $mac, ipv6: $ipv6, interface: $iface, timestamp: $timestamp}')
            CURRENT=$(echo "${INTERFACE_BINDINGS[$IFACE]}" | jq --argjson binding "$BINDING" '. + [$binding]')
            INTERFACE_BINDINGS["$IFACE"]="$CURRENT"
            echo "[$IFACE] Binding encontrado: $ip -> $SRC_MAC"
        }

        # Agregar el binding del origen (usualmente la dirección link-local)
        add_binding "$SRC_IP"

        # Si se detectó una dirección objetivo (podría ser global unicast) y es diferente,
        # se agrega como binding extra.
        if [[ -n "$TARGET_IP" && "$TARGET_IP" != "$SRC_IP" ]]; then
            add_binding "$TARGET_IP"
        fi

    done < <(tcpdump -nn -vv -r "$PCAP_FILE" -e 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)' 2>/dev/null)

    # Liberar la variable 'seen' para la siguiente interfaz
    unset seen
done

# Construir el archivo JSON final
{
  echo "{"
  FIRST=1
  for IFACE in "${INTERFACES[@]}"; do
      if [ "$FIRST" -eq 1 ]; then
          FIRST=0
      else
          echo ","
      fi
      echo -n "  \"$IFACE\": ${INTERFACE_BINDINGS[$IFACE]}"
  done
  echo -e "\n}"
} > "$BINDING_FILE"

# Aplicar deduplicación final con jq (por si hubiera repetidos)
jq 'to_entries | map({key: .key, value: (.value | unique_by(.ipv6))}) | from_entries' "$BINDING_FILE" \
    > "${BINDING_FILE}.tmp" && mv "${BINDING_FILE}.tmp" "$BINDING_FILE"

echo "[✓] Tabla final generada en: $BINDING_FILE"
jq . "$BINDING_FILE"
