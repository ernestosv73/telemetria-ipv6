#!/usr/bin/env python3

import json
import yaml

BINDINGS_FILE = "/data/mac_ipv6_bindings_dynamic.json"
GNMIC_ACTIONS_FILE = "/data/gnmic-actions.yml"
ACL_NAME = "permitidos"
ACL_FILTER_NAME = "icmpv6"

def extract_data():
    prefixes = set()
    interfaces = dict()  # key: full interface (e.g., ethernet-1/2.0), value: (iface, subif)

    with open(BINDINGS_FILE, 'r') as f:
        bindings = json.load(f)
        for entry in bindings:
            for key in ("ipv6_link_local", "ipv6_global"):
                if entry.get(key):
                    prefixes.add(f"{entry[key]}/128")
            iface = entry.get("interface")
            if iface and iface not in interfaces:
                try:
                    base, sub = iface.split(".")
                    interfaces[iface] = (base, int(sub))
                except ValueError:
                    continue  # skip malformed

    return sorted(prefixes), interfaces

def generate_gnmic_yaml(prefixes, interfaces):
    action = {
        "name": "update_acl_config",
        "type": "gnmi",
        "target": "srlswitch",
        "rpc": "set",
        "encoding": "json_ietf",
        "debug": True,
        "paths": [],
        "values": []
    }

    # 1. Prefix list updates
    for prefix in prefixes:
        path = f"/acl/match-list/ipv6-prefix-list[name={ACL_NAME}]/prefix[{prefix}]"
        action["paths"].append(path)
        action["values"].append({})  # empty dict for /128

    # 2. Interface ACL application
    for full_iface, (iface, subif) in interfaces.items():
        base_path = f"/acl/interface[name={full_iface}]"
        action["paths"].append(f"{base_path}/interface-ref/interface")
        action["values"].append(iface)

        action["paths"].append(f"{base_path}/interface-ref/subinterface")
        action["values"].append(subif)

        action["paths"].append(f"{base_path}/input/acl-filter[name={ACL_FILTER_NAME}]/type")
        action["values"].append("ipv6")

    # Full YAML structure
    yaml_data = {
        "username": "admin",
        "password": "NokiaSrl1!",
        "skip-verify": True,
        "encoding": "json_ietf",
        "log": True,
        "actions": {
            "update_acl_config": action
        }
    }

    with open(GNMIC_ACTIONS_FILE, "w") as f:
        yaml.dump(yaml_data, f, default_flow_style=False)

    print(f"[INFO] Archivo generado: {GNMIC_ACTIONS_FILE}")

if __name__ == "__main__":
    prefixes, interfaces = extract_data()
    generate_gnmic_yaml(prefixes, interfaces)
