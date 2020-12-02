# Python-Packet-Sniffer

## Resumo

Esse repositório é um fork do trabalho que pode ser encontrado no seguinte link: 
https://github.com/O-Luhishi/Python-Packet-Sniffer

O software original é um sniffer feito em Python, que busca monitorar a rede em busca de pacotes Ethernet. Inicialmente somente para pacotes IPv4.

A ideia desse fork foi adicionar as seguintes funcionalidades:

## Novas funcionalidades
  - Captação de pacotes IPv6
  - Armazenar em arquivo .pcap os pacotes encontrados.
  - Realizar a abertura de arquivos .pcap para análise.
  - Na leitura de arquivo, filtrar pacotes, por exemplo: UDP - TCP - ICMP 

## Overview

Packet Sniffer created in Python 3. Allows you to monitor traffic running through local network. Allows the user to be able to view Source of the packets, Target host and the type of protocol used e.g. UDP/TCP.

## Requirement
  - Python 3.x
  - Privileged/Administrative Rights
  - Linux or Windows Operating System


## Exemplos
  - Monitorando a rede 
  Ao iniciar o software, você decide se quer monitorar a rede ou abrir um arquivo .pcap.
  No exemplo decidimos monitorar a rede, então é solicitado o nome do arquivo para salvar os pacotes e também a quantidade pacotes a serem capturados.

  ![Alt text](images/menu_inicial.png?raw=true "Menu")
