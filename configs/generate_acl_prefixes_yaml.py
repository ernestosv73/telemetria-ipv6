#!/usr/bin/env python3

import json
from pathlib import Path
from ruamel.yaml import YAML

BINDINGS_FILE = "/data/mac_ipv6_bindings_dynamic.json"
GNMIC_ACTIONS_FILE = "/data/gnmic-actions.yml"
ACL_NAME = "permitidos"

def extract_prefixes():
    prefixes = set()
    with open(BINDINGS_FILE, 'r') as f:
        bindings = json.load(f)
        for entry in bindings:
            for key in ("ipv6_link_local", "ipv6_global"):
                if entry.get(key):
                    prefixes.add(f"{entry[key]}/128")
    return sorted(prefixes)

def generate_gnmic_yaml(prefixes):
    yaml = YAML()
    data = {
        "username": "admin",
        "password": "NokiaSrl1!",
        "skip-verify": True,
        "encoding": "json_ietf",
        "log": True,
        "actions": {
            "update_ipv6_prefix_list": {
                "name": "update_ipv6_prefix_list",
                "type": "gnmi",
                "target": "srlswitch",
                "rpc": "set",
                "encoding": "json_ietf",
                "debug": True,
                "paths": [],
                "values": []
            }
        }
    }

    for prefix in prefixes:
        path = f"/acl/match-list/ipv6-prefix-list[name={ACL_NAME}]/prefix[{prefix}]"
        data["actions"]["update_ipv6_prefix_list"]["paths"].append(path)
        data["actions"]["update_ipv6_prefix_list"]["values"].append({})

    with open(GNMIC_ACTIONS_FILE, 'w') as f:
        yaml.dump(data, f)

    print(f"[INFO] Archivo generado: {GNMIC_ACTIONS_FILE}")

if __name__ == "__main__":
    prefixes = extract_prefixes()
    generate_gnmic_yaml(prefixes)
