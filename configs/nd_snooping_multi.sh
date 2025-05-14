#!/bin/bash

INTERFACES=("e1-2" "e1-3" "e1-4")
DURATION=30
OUTPUT="/root/bindings.json"
TMP_DIR="/tmp/nd_snoop"
VALID_PREFIXES=("fe80::" "2001:db8:20:")

mkdir -p "$TMP_DIR"
rm -f "$TMP_DIR"/*.log "$OUTPUT"

echo "[*] Capturando mensajes ND durante $DURATION segundos..."

# Captura ND por interfaz (NS=135, NA=136)
for intf in "${INTERFACES[@]}"; do
    tcpdump -i "$intf" -v -n -l -c 1000 'icmp6 and (ip6[40] = 135 or ip6[40] = 136)' > "$TMP_DIR/$intf.log" 2>/dev/null &
done

sleep "$DURATION"
pkill tcpdump 2>/dev/null

echo "[*] Procesando mensajes ND..."

declare -A binding_map
timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

for intf in "${INTERFACES[@]}"; do
    file="$TMP_DIR/$intf.log"
    [[ ! -f "$file" ]] && continue

    mac="" ; ipv6="" ; tlla=""
    while read -r line; do
        # Captura MAC, dirección IPv6 y TLLA
        [[ "$line" =~ ^[0-9]{2}:[0-9]{2}:[0-9]{2}.* > ([0-9a-f:]+), ethertype IPv6 ]] && mac="${BASH_REMATCH[1]}"
        # Captura direcciones IPv6 (tanto link-local como global unicast)
        [[ "$line" =~ ICMP6, neighbor (solicitation|advertisement).*([a-f0-9:]+) ]] && ipv6="${BASH_REMATCH[1]}"
        [[ "$line" =~ option.*link-layer address.*([0-9a-f:]{17}) ]] && tlla="${BASH_REMATCH[1]}"

        if [[ -n "$mac" && -n "$ipv6" && -n "$tlla" ]]; then
            # Validación 1: MAC == TLLA
            [[ "$mac" != "$tlla" ]] && { mac="" ; ipv6="" ; tlla="" ; continue; }

            # Validación 2: Prefijo válido (fe80:: o 2001:db8:20:)
            valid_prefix=false
            for prefix in "${VALID_PREFIXES[@]}"; do
                if [[ "$ipv6" == "$prefix"* ]]; then
                    valid_prefix=true
                    break
                fi
            done
            $valid_prefix || { mac="" ; ipv6="" ; tlla="" ; continue; }

            # Validación 3: no duplicado
            key="${intf}_${mac}_${ipv6}"
            if [[ -z "${binding_map[$key]}" ]]; then
                binding_map["$key"]="{\"mac\":\"$mac\",\"ipv6\":\"$ipv6\",\"interface\":\"$intf\",\"timestamp\":\"$timestamp\"}"
                echo "[$intf] Binding válido: $ipv6 -> $mac"
            fi

            mac="" ; ipv6="" ; tlla=""
        fi
    done < "$file"
done

# Construir bindings.json
echo "{" > "$OUTPUT"
for intf in "${INTERFACES[@]}"; do
    echo "  \"$intf\": [" >> "$OUTPUT"
    count=0
    for key in "${!binding_map[@]}"; do
        if [[ "$key" == "$intf"_* ]]; then
            [[ $count -ne 0 ]] && echo "," >> "$OUTPUT"
            echo -n "    ${binding_map[$key]}" >> "$OUTPUT"
            ((count++))
        fi
    done
    echo -e "\n  ]," >> "$OUTPUT"
done
sed -i '$ s/],/]/' "$OUTPUT"
echo "}" >> "$OUTPUT"

echo "[✓] Tabla final en: $OUTPUT"
jq . "$OUTPUT"
