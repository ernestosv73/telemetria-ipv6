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
| gnmic_subscribe_mactable |mode: stream / stream-mode: on-change  
| Switch |Aruba AOS-CX 10.14
|PC1 y PC3|Kali Linux con THC IPv6 Tool e IPv6Toolkit 
|PC2 y PC4|Alpine Linux


