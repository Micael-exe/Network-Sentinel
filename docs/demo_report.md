# Network Sentinel - Relatório

Gerado em **2026-10-14T18:58:38** | Sub-rede **192.168.1.0/24** | Última varredura **2026-10-14T18:58:38**

- Dispositivos: **11** (8 confiáveis, 3 desconhecidos)
- Alertas abertos: **16** (críticos: 1, altos: 4, médios: 2)

## Alertas

| Sev. | Tipo | Quando | Mensagem |
|---|---|---|---|
| CRÍTICO | GATEWAY_CHANGED | 2026-10-14T18:58:38 | O MAC do gateway 192.168.1.1 mudou de a4:2b:b0:11:22:33 (TP-Link) para 00:0c:29:de:ad:be (VMware, Inc.). Possível ARP spoofing / man-in-the-middle ou roteador substituído. |
| ALTO | NEW_DEVICE | 2026-10-14T18:58:38 | Dispositivo desconhecido entrou na rede: esp32-desconhecido [Espressif]. |
| ALTO | NEW_DEVICE | 2026-10-14T18:58:38 | Dispositivo desconhecido entrou na rede: sem identificação [fabricante desconhecido]. MAC randomizado (típico de celulares com 'endereço Wi-Fi privado'). |
| ALTO | RISKY_PORT | 2026-10-14T18:58:38 | Porta de risco aberta em camera-sala: 23/tcp - telnet - Telnet (sem criptografia) |
| ALTO | NEW_DEVICE | 2026-10-14T18:58:38 | Dispositivo desconhecido entrou na rede: VMware, Inc. [VMware, Inc.]. |
| MÉDIO | NEW_PORT | 2026-10-14T18:58:38 | Nova porta aberta em camera-sala: 8080/tcp - http-proxy |
| MÉDIO | HOSTNAME_CHANGED | 2026-10-14T18:58:38 | Hostname mudou: 'raspberrypi' -> 'kali-unknown' (mesmo MAC; verifique se o equipamento foi reconfigurado). |
| BAIXO | DEVICE_RETURNED | 2026-10-14T18:58:38 | smart-tv reapareceu após 20 dias ausente. |
| BAIXO | IP_CHANGED | 2026-10-14T18:58:38 | MacBook da Ana mudou de IP: 192.168.1.10 -> 192.168.1.15 |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | Câmera da sala reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | impressora reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | hue-bridge reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | chromecast reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | Raspberry Pi reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | MacBook da Ana reapareceu após 18 dias ausente. |
| BAIXO | DEVICE_RETURNED | 2026-10-12T18:58:38 | roteador.lan reapareceu após 18 dias ausente. |

## Inventário de dispositivos

| Status | IP | MAC | Fabricante | Nome | Portas | Último visto |
|---|---|---|---|---|---|---|
| **DESCONHECIDO** | 192.168.1.1 | `00:0c:29:de:ad:be` | VMware, Inc. | - | 80, 443 | 2026-10-14T18:58:38 |
| **DESCONHECIDO** | 192.168.1.99 | `02:5b:9e:ab:cd:ef` | - | - | - | 2026-10-14T18:58:38 |
| **DESCONHECIDO** | 192.168.1.101 | `e8:db:84:12:90:ab` | Espressif | esp32-desconhecido | 80 | 2026-10-14T18:58:38 |
| confiável | 192.168.1.1 | `a4:2b:b0:11:22:33` | TP-Link | roteador.lan | 80, 443 | 2026-10-12T18:58:38 |
| confiável | 192.168.1.11 | `dc:a6:32:12:34:56` | Raspberry Pi | Raspberry Pi | 22 | 2026-10-14T18:58:38 |
| confiável | 192.168.1.15 | `3c:22:fb:aa:bb:01` | Apple | MacBook da Ana | - | 2026-10-14T18:58:38 |
| confiável | 192.168.1.20 | `f4:f5:d8:55:66:77` | Google | chromecast | - | 2026-10-14T18:58:38 |
| confiável | 192.168.1.30 | `00:17:88:0a:0b:0c` | Philips Lighting | hue-bridge | 80 | 2026-10-14T18:58:38 |
| confiável | 192.168.1.50 | `00:1b:a9:44:55:66` | Brother Industries | impressora | 631 | 2026-10-14T18:58:38 |
| confiável | 192.168.1.60 | `8c:79:f5:77:88:99` | Samsung | smart-tv | - | 2026-10-14T18:58:38 |
| confiável | 192.168.1.70 | `c0:56:e3:de:ad:01` | Hikvision | Câmera da sala | 23, 80, 554, 8080 | 2026-10-14T18:58:38 |

## Histórico de varreduras

| # | Data | Hosts | Novos | Alertas |
|---|---|---|---|---|
| 3 | 2026-10-14T18:58:38 | 10 | 3 | 9 |
| 2 | 2026-10-12T18:58:38 | 7 | 0 | 7 |
| 1 | 2026-09-24T18:58:38 | 8 | 8 | 0 |
