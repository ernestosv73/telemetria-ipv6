#!/bin/bash

# Interfaces y archivos
INTERFACE="eth0"
PCAP_FILE="/tmp/ndp.pcap"
JSON_FILE="/tmp/ipv6_ndp.json"

# Limpieza al salir
cleanup() {
  echo "[*] Terminando procesos..."
  if [[ -n "$TCPDUMP_PID" ]]; then
    kill "$TCPDUMP_PID" 2>/dev/null
  fi
  exit 0
}
trap cleanup INT TERM

# Paso 1: Iniciar captura tcpdump (modo background)
echo "[*] Iniciando captura de paquetes NDP en $INTERFACE..."
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" 'icmp6 && (ip6[40] == 135 or ip6[40] == 136)' &
TCPDUMP_PID=$!
sleep 1  # Espera para asegurarse que tcpdump arrancó

# Paso 2: Procesamiento periódico del archivo .pcap
echo "[*] Procesando tráfico NDP cada 2 segundos..."
while true; do
  tshark -r "$PCAP_FILE" -T json > "$JSON_FILE"
  echo "[*] JSON actualizado: $(date)"
  sleep 2
done
