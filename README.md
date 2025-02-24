# Laboratorio Seguridad en IPv6 con Containerlab
---
<div align=center markdown>
<a href="https://codespaces.new/ernestosv73/nokia24?quickstart=1">
<img src="https://gitlab.com/rdodin/pics/-/wikis/uploads/d78a6f9f6869b3ac3c286928dd52fa08/run_in_codespaces-v1.svg?sanitize=true" style="width:50%"/></a>

**[Run](https://codespaces.new/ernestosv73/nokia24?quickstart=1) this lab in GitHub Codespaces for free**.  
[Learn more](https://containerlab.dev/manual/codespaces) about Containerlab for Codespaces.  
<small>Machine type: 2 vCPU · 8 GB RAM</small>
</div>

---
Este laboratorio de pruebas tiene como objetivo proporcionar una topología de red basada en Containerlab que permita comprender el funcionamiento de los protocolos involucrados en el proceso de autoconfiguración de direcciones IPv6 mediante SLAAC.

## Descripción Topología

La topología de red desplegada contiene un dispositivo Nokia SRL Linux configurado como router, conectado a otro Nokia SRL configurado como Switch. La topología se completa con 4 dispositivos Hosts Kali Linux que contienen las herramientas IPv6 Toolkit y THC-IPv6.
