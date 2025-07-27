# Telemetría aplicada a la automatización de seguridad en redes IPv6 con Containerlab
---
<div align=center markdown>
<a href="https://codespaces.new/ernestosv73/nokia24?quickstart=1">
<img src="https://gitlab.com/rdodin/pics/-/wikis/uploads/d78a6f9f6869b3ac3c286928dd52fa08/run_in_codespaces-v1.svg?sanitize=true" style="width:50%"/></a>

**[Run](https://codespaces.new/ernestosv73/telemetria-ipv6?quickstart=1) this lab in GitHub Codespaces for free**.  
[Learn more](https://containerlab.dev/manual/codespaces) about Containerlab for Codespaces.  
<small>Machine type: 2 vCPU · 8 GB RAM</small>
</div>

---
La topología creada provee un laboratorio de pruebas para la automatización de seguridad en Redes IPv6 basado en los protocolos gNMI, JSON-RPC, integrado con Scapy y Python. 

## Funcionalidad nodo gNMIc

| Script |Funcionalidad  |
|--|--|
| gnmic_subscribe_mactable |mode: stream / stream-mode: on-change / output file: mac_updates.json  
|                 |Captura tráfico ICMPv6 RS NS en proceso SLAAC.
| icmpv6_captura* | Correlaciona tráfico capturado con archivo mac_updates.json 
|                 | Output file: mac_ipv6_bindings_dynamic.json
| sync_bindings* | Input file: mac_ipv6_bindings_dynamic.json 
|                | Genera ACLs por interface y envía a Nokia Switch vía JSON-RPC  
|PC2 y PC4|Alpine Linux


