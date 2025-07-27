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
![Alt text](imagenes/diagram-export-27-7-2025-01_40_54.png)

## Funcionalidad nodo gNMIc

| Script |Funcionalidad  |
|--|--|
| gnmic_subscribe_mactable |Descubrimiento automático de nodos que se conectan a la red, (port, mac-addrs) / output file: mac_updates.json  
| icmpv6_captura* |Captura tráfico ICMPv6 RS NS en proceso SLAAC.
|                 | Correlaciona tráfico capturado con archivo mac_updates.json 
|                 | Output file: mac_ipv6_bindings_dynamic.json
| sync_bindings* | Genera ACLs por interface y envía a Nokia Switch vía JSON-RPC
|                | Input file: mac_ipv6_bindings_dynamic.json  
| gnmic_subscribe_acl| Suscripción de métricas ACL match packets y envío a Stack Telemetría Prometheus/Grafana

* Todos los scripts fueron integrados y controlados por el Sistema de Control de Procesos Supervisord.
* Acceder al nodo gNMIc ejecutando: `docker exec -it clab-telemetria-gNMIc /bin/bash`. Desde el directorio root, ejecutar `supervisord -c supervisord.conf`
  
## Conexión a los nodos PC1, PC2, PC4
* `docker exec -it clab-telemetria-PCx /bin/bash`
* Simular la conexión a la red ejecuntado: `ifconfig eth1 down` `ifconfig eth1 up`

## Stack Telemetría
* Visualización de métricas en Grafana / Dashboard Telemetría IPv6
* Acceder desde navegador en host local a la url: `http://ip-hostlocal:3000`
  
## Ejemplos ataques
### Flooding neighbor advertisements (atk6-flood_advertise6). 
>From https://www.kali.org/tools/thc-ipv6/
* Desde **PC1**
  *  Lanzar el ataque ejecutando: `atk6-flood_advertise6 eth1`
