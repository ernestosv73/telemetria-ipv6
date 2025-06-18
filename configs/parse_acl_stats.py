import json
from datetime import datetime

input_file = "/data/acl_statistics.json"
output_file = "/data/acl_matched_packets_summary.json"

results = []

with open(input_file, "r") as infile:
    for line in infile:
        try:
            data = json.loads(line)
            # Filtramos líneas que contengan updates válidos
            if "updates" in data:
                for update in data["updates"]:
                    path = update.get("Path", "")
                    if "interface-id=" in path:
                        # Extraer nombre de la interfaz
                        interface = path.split("interface-id=")[1].split("]")[0]
                        matched_packets_str = update["values"]["srl_nokia-acl:acl/interface/input/acl-filter/entry/statistics"]["matched-packets"]
                        matched_packets = int(matched_packets_str)
                        timestamp = data.get("time")
                        results.append({
                            "timestamp": timestamp,
                            "interface": interface,
                            "matched_packets": matched_packets
                        })
        except json.JSONDecodeError:
            continue  # Ignorar líneas inválidas como {"sync-response":true}

# Guardar el resultado en un nuevo archivo
with open(output_file, "w") as outfile:
    json.dump(results, outfile, indent=2)

print(f"[✔] Archivo generado: {output_file} con {len(results)} entradas.")
