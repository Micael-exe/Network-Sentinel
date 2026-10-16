# 🛡️ Network Sentinel

Ferramenta em **Python** para monitorar a sua **rede doméstica**: descobre dispositivos com **Nmap**, guarda o histórico em SQLite, analisa tráfego com **tshark (Wireshark)**, dispara **alertas** de comportamento suspeito e gera **relatórios** em HTML/Markdown.

> ⚠️ Use **somente em redes que você administra**. Varrer redes de terceiros pode ser ilegal.

- Sem dependências Python externas (só biblioteca padrão)
- Testado para Kali Linux (funciona em qualquer Linux com `nmap` e `tshark`)
- 🔎 Veja um relatório de exemplo em [`docs/demo_report.html`](docs/demo_report.html) / [`docs/demo_report.md`](docs/demo_report.md)

## Funcionalidades

| Recurso | Como funciona |
|---|---|
| **Inventário de IPs** | `nmap -sn` (ARP sweep) → IP, MAC, fabricante, hostname |
| **Histórico de dispositivos** | primeira/última vez visto, nº de varreduras, histórico de IPs, portas |
| **Alertas** | regras comparam cada varredura com o histórico (tabela abaixo) |
| **Análise de tráfego** | `tshark` captura ao vivo ou lê `.pcap` salvo no Wireshark |
| **Relatórios** | HTML autocontido (claro/escuro) e Markdown |
| **Monitoramento contínuo** | `watch` ou serviço `systemd` |

### Regras de detecção

| Alerta | Severidade | Quando dispara |
|---|---|---|
| `GATEWAY_CHANGED` | 🔴 crítica | O MAC do gateway mudou (possível ARP spoofing / MITM) |
| `ARP_SPOOFING` | 🔴 crítica/alta | Um mesmo IP anunciado via ARP por MACs diferentes (captura) |
| `NEW_DEVICE` | 🟠 alta | MAC fora do inventário entrou na rede |
| `RISKY_PORT` | 🟠 alta | Telnet, RDP, SMB, VNC, FTP, UPnP, TR-069... abertos |
| `ARP_FLOOD` / `UNKNOWN_TRAFFIC` | 🟠 alta | Excesso de respostas ARP / tráfego de MAC desconhecido |
| `HOSTNAME_CHANGED` | 🟡 média | Mesmo MAC com outro hostname |
| `NEW_PORT` / `MAC_MULTI_IP` / `TRAFFIC_SPIKE` | 🟡 média | Porta nova / MAC respondendo por ≥3 IPs / pico de volume |
| `IP_CHANGED` / `DEVICE_RETURNED` | 🔵 baixa | Mudou de IP / voltou após longo período ausente |

Alertas repetidos são deduplicados por 6 h. MACs randomizados (Wi-Fi privado de iPhone/Android) são sinalizados como tal para reduzir falsos positivos.

## Instalação (Kali Linux)

```bash
git clone https://github.com/SEU_USUARIO/network-sentinel.git
cd network-sentinel
./scripts/setup_kali.sh        # instala nmap + tshark e roda os testes
```

Ou manualmente: `sudo apt install -y nmap tshark python3`.

## Ativação / primeiros passos

```bash
# 1) Demonstração (não precisa de root nem de rede)
python3 -m netsentinel demo
xdg-open reports/demo_report.html

# 2) Baseline: o que existe hoje na sua rede é considerado confiável
sudo python3 -m netsentinel scan --learn --ports

# 3) Dê nomes aos seus aparelhos
python3 -m netsentinel devices
python3 -m netsentinel trust AA:BB:CC:DD:EE:FF --label "iPhone do João"

# 4) A partir daqui, qualquer novidade vira alerta
sudo python3 -m netsentinel scan --ports
python3 -m netsentinel alerts

# 5) Relatório
python3 -m netsentinel report                  # HTML em reports/
python3 -m netsentinel report --format md -o relatorio.md
```

> `scan` e `capture` precisam de **root** (leitura de MACs via ARP e captura de pacotes). O banco e os relatórios continuam pertencendo ao seu usuário mesmo rodando com `sudo`.

### Todos os comandos

```
scan      varre e analisa      (--subnet, --ports, --top-ports, --learn, --absent-days)
watch     varredura contínua   (--interval 300 + opções do scan)
devices   lista inventário
alerts    lista alertas        (--all inclui os já vistos)
ack       marca como visto     (ID ou --all)
trust     confia/rotula        (MAC --label "nome" | --all | --untrust)
history   histórico de um MAC
capture   tráfego via tshark   (--iface, --duration, --pcap arquivo, --max-mb)
report    gera relatório       (--format html|md, -o arquivo)
serve     painel web ao vivo   (--port, --host, --refresh)
telegram  setup | test         (notificações)
demo      dados de demonstração
```

### Painel ao vivo (relatório que atualiza sozinho)

```bash
python3 -m netsentinel serve                         # http://localhost:8000
sudo python3 -m netsentinel watch --ports --serve    # escaneia e serve ao mesmo tempo
```

O relatório é gerado do banco a cada acesso e a página se atualiza a cada 10 s (`--refresh N`), sem perder a posição da rolagem. Também expõe `/report.md` e `/api.json`. Por padrão escuta só em `127.0.0.1`; use `--host 0.0.0.0` para abrir a outros aparelhos da rede (**sem senha**, só em rede doméstica confiável).

### Notificações no Telegram

```bash
python3 -m netsentinel telegram setup      # assistente: token do @BotFather + descobre seu chat_id
python3 -m netsentinel telegram test       # mensagem de teste

sudo python3 -m netsentinel scan --notify                      # avisa alertas ALTO e CRÍTICO
sudo python3 -m netsentinel watch --ports --serve --notify --report-every 24
python3 -m netsentinel report --send       # gera o HTML e envia como anexo
```

- `--notify-level critical|high|medium|low` define a severidade mínima (padrão: `high`).
- Os alertas de uma varredura vão agrupados em **uma** mensagem, e a deduplicação de 6 h evita repetição.
- O token fica em `.env` (permissão 600, ignorado pelo git). **Nunca** publique esse arquivo; se vazar, use `/revoke` no @BotFather.
- Se o Telegram estiver fora do ar, o monitoramento continua e só registra o erro.
- Atenção à privacidade: mensagens de bot não têm criptografia de ponta a ponta e o relatório lista MACs/IPs da sua rede.

### Integração com o Wireshark

```bash
# Capture no Wireshark (ou: sudo tshark -i wlan0 -a duration:60 -w captura.pcap) e analise:
python3 -m netsentinel capture --pcap captura.pcap

# Ou capture ao vivo por 60 s:
sudo python3 -m netsentinel capture --iface eth0 --duration 60
```

## Rodando como serviço (monitoramento 24/7)

```bash
sudo cp -r . /opt/network-sentinel
sudo cp systemd/netsentinel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netsentinel
journalctl -u netsentinel -f
# relatório quando quiser:
sudo NETSENTINEL_DB=/var/lib/network-sentinel/sentinel.db python3 -m netsentinel report -o /tmp/relatorio.html
```

Alternativa com cron (a cada 10 min): `*/10 * * * * cd /opt/network-sentinel && /usr/bin/python3 -m netsentinel scan --ports >> /var/log/netsentinel.log 2>&1`

## Estrutura

```
netsentinel/
  cli.py        comandos         scanner.py   nmap (XML) + info da interface
  analyzer.py   regras/alertas   capture.py   tshark: ARP spoofing, tráfego
  db.py         SQLite           report.py    HTML / Markdown
  demo.py       dados de teste   models.py    Host, Port
tests/          testes (unittest)    systemd/   serviço    scripts/   setup
```

Testes: `python3 -m unittest discover -s tests -v`

## Ideias para evoluir

Notificação por e-mail, ações no painel web, detecção de DNS suspeito, exportação para JSON/CSV, dispositivos "offline há muito tempo".

## Licença

MIT
