# Laboratorio Seguridad en IPv6 con Containerlab
Este laboratorio de pruebas tiene como objetivo proporcionar una topología de red basada en Containerlab que permita comprender el funcionamiento de los protocolos involucrados en el proceso de autoconfiguración de direcciones IPv6 mediante SLAAC.

## Description

The lab consists of an Nokia SR Linux router node connected to another Nokia SR Linux node configured as a switch. Three host nodes are also connected to the switch:
PC1 and PC2: Kali Linux OS. Image based on kali-rolling with packages net-tools, iproute2, ipv6toolkit and Thc-Ipv6.
PC3: Alpine Linux with net tools.
