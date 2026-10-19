"""Interface de linha de comando do Network Sentinel."""
import argparse
import getpass
import os
import sys
import time
from datetime import datetime

from . import __version__, analyzer, capture, notify, report, scanner, server
from .db import Database, _chown_to_sudo_user, ensure_dir, normalize_mac, now
from .notify import TelegramError
from .scanner import ScanError

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
          "low": "\033[36m", "info": "\033[90m"}


def paint(sev: str, text: str) -> str:
    return f"{COLORS.get(sev, '')}{text}\033[0m" if sys.stdout.isatty() else text


def print_alerts(alerts):
    for a in alerts:
        tag = paint(a["severity"], f"[{a['severity'].upper():8}]")
        print(f" {tag} #{a['id']:<4} {a['kind']:<16} {a['message']}")


def table(rows, headers):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    line = lambda r: "  ".join(str(c).ljust(w) for c, w in zip(r, widths))
    print(line(headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(line(r))


# ---------------------------------------------------------------- comandos
def _require_telegram():
    cfg = notify.load_config()
    if not cfg:
        raise ScanError("Telegram não configurado. Rode: python3 -m netsentinel telegram setup")
    return cfg


def _notify(alerts, level):
    """Envia alertas novos; nunca derruba o monitoramento se o Telegram falhar."""
    try:
        n = notify.notify_alerts(_require_telegram(), alerts, level)
        if n:
            print(f"[+] Telegram: {n} alerta(s) enviado(s).")
    except (TelegramError, ScanError) as exc:
        print(f"[!] Telegram: {exc}")


def _write_report(db, fmt="html"):
    out = os.path.join("reports", f"report_{datetime.now():%Y%m%d_%H%M%S}.{fmt}")
    ensure_dir("reports")
    with open(out, "w", encoding="utf-8") as f:
        f.write(report.render(db, fmt))
    _chown_to_sudo_user(out)
    return out


def _send_report(db, path=None):
    cfg = _require_telegram()
    data = report.collect(db)
    path = path or _write_report(db, "html")
    caption = (f"🛡️ Network Sentinel — {len(data['devices'])} dispositivos, "
               f"{len(data['alerts'])} alertas abertos "
               f"({data['sev']['critical'] + data['sev']['high']} críticos/altos)")
    notify.Telegram(*cfg).send_document(path, caption)
    print("[+] Telegram: relatório enviado.")


def run_scan(db: Database, args) -> dict:
    if os.geteuid() != 0:
        raise ScanError("A varredura precisa de root para ler MACs via ARP. "
                        "Rode com: sudo python3 -m netsentinel scan")
    info = scanner.local_info()
    subnet = args.subnet or info.network
    print(f"[*] Interface {info.iface} | seu IP {info.ip} | gateway {info.gateway} | alvo {subnet}")
    hosts = scanner.discover(subnet, info)
    print(f"[*] {len(hosts)} host(s) ativo(s). ", end="")
    if args.ports:
        print(f"Varrendo as {args.top_ports} portas mais comuns (pode demorar)...")
        scanner.port_scan(hosts, args.top_ports)
    else:
        print("(use --ports para varrer portas)")
    result = analyzer.process_scan(db, hosts, subnet, info.gateway, learn=args.learn,
                                   absent_days=args.absent_days)
    print(f"[+] Varredura #{result['scan_id']}: {result['hosts']} dispositivo(s), "
          f"{result['new_devices']} novo(s), {len(result['alerts'])} alerta(s).")
    if result["skipped_no_mac"]:
        print(f"[!] {result['skipped_no_mac']} host(s) sem MAC ignorado(s) (outra sub-rede / sem root?).")
    if args.learn:
        print("[+] Modo --learn: todos os dispositivos atuais foram marcados como confiáveis.")
    print_alerts(result["alerts"])
    if args.notify:
        _notify(result["alerts"], args.notify_level)
    return result


def cmd_scan(db, args):
    if args.notify:
        _require_telegram()
    run_scan(db, args)


def _start_server(args):
    if args.host != "127.0.0.1":
        print("[!] Painel exposto na rede SEM senha. Use só em rede doméstica confiável.")
    server.serve(args.db, args.host, args.port, args.refresh, block=False)
    print(f"[+] Painel ao vivo: http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}")


def cmd_serve(db, args):
    print(f"[+] Painel ao vivo: http://localhost:{args.port}  (Ctrl+C para parar)")
    if args.host != "127.0.0.1":
        print("[!] Exposto na rede SEM senha. Use só em rede doméstica confiável.")
    server.serve(args.db, args.host, args.port, args.refresh)


def cmd_watch(db, args):
    if args.notify or args.report_every:
        _require_telegram()
    next_report = time.time() + args.report_every * 3600 if args.report_every else None
    if args.serve:
        _start_server(args)
    print(f"[*] Monitorando a cada {args.interval}s. Ctrl+C para parar.")
    try:
        while True:
            print(f"\n=== {now()} ===")
            try:
                run_scan(db, args)
            except (ScanError, OSError) as exc:
                print(f"[!] {exc}")
            if next_report and time.time() >= next_report:
                try:
                    _send_report(db)
                except (TelegramError, ScanError, OSError) as exc:
                    print(f"[!] Telegram: {exc}")
                next_report += args.report_every * 3600
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Encerrado.")


def cmd_devices(db, args):
    rows = [("OK" if d["trusted"] else "??", d["ip"] or "-", d["mac"], (d["vendor"] or "-")[:22],
             (d["label"] or d["hostname"] or "-")[:24], d["last_seen"]) for d in db.list_devices()]
    if not rows:
        print("Inventário vazio. Rode: sudo python3 -m netsentinel scan --learn")
        return
    table(rows, ["", "IP", "MAC", "Fabricante", "Nome", "Último visto"])
    print("\nOK = confiável | ?? = desconhecido")


def cmd_alerts(db, args):
    alerts = db.list_alerts(only_open=not args.all)
    if not alerts:
        print("Nenhum alerta.")
    print_alerts(alerts)


def cmd_ack(db, args):
    if not args.id and not args.all:
        raise SystemExit("Informe um ID ou use --all.")
    n = db.ack(None if args.all else args.id)
    print(f"{n} alerta(s) marcado(s) como visto(s).")


def cmd_trust(db, args):
    if args.all:
        for d in db.list_devices():
            db.update_device(d["mac"], trusted=1)
        print("Todos os dispositivos marcados como confiáveis.")
        return
    if not args.mac:
        raise SystemExit("Informe um MAC ou use --all.")
    mac = normalize_mac(args.mac)
    if not db.get_device(mac):
        raise SystemExit(f"MAC {mac} não está no inventário.")
    fields = {"trusted": 0 if args.untrust else 1}
    if args.label:
        fields["label"] = args.label
    db.update_device(mac, **fields)
    print(f"{mac} -> {'não confiável' if args.untrust else 'confiável'}"
          + (f" ('{args.label}')" if args.label else ""))


def cmd_forget(db, args):
    if args.all_untrusted:
        targets = [d["mac"] for d in db.list_devices() if not d["trusted"]]
        if not targets:
            print("Nenhum dispositivo desconhecido para remover.")
            return
        if not args.yes:
            print(f"Isso vai remover {len(targets)} dispositivo(s) desconhecido(s) e todo o "
                  f"histórico deles (IPs, portas, alertas). Esta ação não pode ser desfeita.")
            if input("Confirma? [s/N]: ").strip().lower() not in ("s", "sim", "y", "yes"):
                print("Cancelado.")
                return
        for mac in targets:
            db.forget_device(mac)
        print(f"[+] {len(targets)} dispositivo(s) removido(s) do inventário.")
        return
    if not args.mac:
        raise SystemExit("Informe um MAC ou use --all-untrusted.")
    mac = normalize_mac(args.mac)
    dev = db.get_device(mac)
    if not dev:
        raise SystemExit(f"MAC {mac} não está no inventário.")
    if not args.yes:
        who = dev["label"] or dev["hostname"] or dev["vendor"] or mac
        print(f"Isso vai remover '{who}' ({mac}) e todo o histórico dele (IPs, portas, alertas).")
        print("Se o aparelho continuar na rede, ele volta como NOVO na próxima varredura.")
        if input("Confirma? [s/N]: ").strip().lower() not in ("s", "sim", "y", "yes"):
            print("Cancelado.")
            return
    db.forget_device(mac)
    print(f"[+] {mac} removido do inventário.")


def cmd_history(db, args):
    mac = normalize_mac(args.mac)
    d = db.get_device(mac)
    if not d:
        raise SystemExit("MAC não encontrado.")
    print(f"{d['label'] or d['hostname'] or '-'}  {mac}  [{d['vendor'] or '?'}]")
    print(f"Primeira vez: {d['first_seen']} | Última: {d['last_seen']} | "
          f"Vistos em {db.sighting_count(mac)} varredura(s)")
    print("\nHistórico de IPs:")
    for h in db.ip_history(mac):
        print(f"  {h['ip']:<16} {h['first_seen']} -> {h['last_seen']}")
    print("\nPortas abertas:")
    for p in db.open_ports(mac) or []:
        print(f"  {p['port']}/{p['proto']} {p['service'] or ''} {p['version'] or ''}")


def run_capture(db, args, iface, gw):
    src = args.pcap or f"{iface} por {args.duration}s"
    print(f"[*] Analisando tráfego: {src}")
    packets = capture.run_tshark(iface, args.duration, args.pcap)
    res = capture.analyze_packets(db, packets, gw, args.max_mb)
    print(f"[+] {res['packets']} pacotes. Maiores emissores:")
    for t in res["talkers"]:
        print(f"    {t['mac']}  {t['bytes']/1e6:8.2f} MB  {t['name']}")
    print_alerts(res["alerts"] or [])
    if not res["alerts"]:
        print("[+] Nenhuma anomalia no tráfego capturado.")
    elif args.notify:
        _notify(res["alerts"], args.notify_level)
    return res


def cmd_capture(db, args):
    if args.notify:
        _require_telegram()
    if not args.pcap and os.geteuid() != 0:
        raise ScanError("A captura ao vivo precisa de root: sudo python3 -m netsentinel capture ...")
    iface, gw = args.iface, None
    try:
        info = scanner.local_info()
        iface, gw = iface or info.iface, info.gateway
    except ScanError:
        pass
    if not args.loop:
        run_capture(db, args, iface, gw)
        return
    print(f"[*] Vigiando {iface} em janelas de {args.duration}s, sem parar. Ctrl+C para sair.")
    try:
        while True:
            print(f"\n=== {now()} ===")
            try:
                run_capture(db, args, iface, gw)
            except (ScanError, OSError) as exc:
                print(f"[!] {exc}")
    except KeyboardInterrupt:
        print("\n[*] Encerrado.")


def cmd_telegram(_db, args):
    if args.action == "test":
        notify.Telegram(*_require_telegram()).send_message(
            "✅ <b>Network Sentinel</b> conectado ao Telegram.")
        print("[+] Mensagem de teste enviada. Confira o seu Telegram.")
        return
    print("== Configuração do Telegram ==")
    if os.path.isfile(".env") and not os.environ.get("NETSENTINEL_ENV"):
        print(f"[!] Encontrei um .env antigo em {os.path.abspath('.env')} (versão anterior).")
        print("    Ele continua valendo enquanto você rodar os comandos nesta pasta.")
        print("    A partir de agora, as novas credenciais vão para um local fixo,")
        print("    que funciona em qualquer pasta e com ou sem sudo.\n")
    print("1) No Telegram, converse com @BotFather, envie /newbot e copie o TOKEN.\n")
    token = getpass.getpass("Cole o token (não aparece ao digitar): ").strip()
    if not token:
        raise ValueError("Token vazio.")
    tg = notify.Telegram(token, "")
    me = tg.get_me()
    print(f"[+] Bot encontrado: @{me.get('username')}\n")
    input(f"2) Abra @{me.get('username')} no Telegram, toque em Iniciar e envie qualquer "
          f"mensagem.\n   Depois aperte Enter aqui... ")
    chats = tg.get_chat_ids()
    if chats:
        for i, (cid, name, kind) in enumerate(chats, 1):
            print(f"   {i}) {name} ({kind}) - id {cid}")
        pick = (input("Qual é você? [1]: ").strip() or "1")
        if not pick.isdigit() or not 1 <= int(pick) <= len(chats):
            raise ValueError("Opção inválida.")
        chat_id = str(chats[int(pick) - 1][0])
    else:
        chat_id = input("Nenhuma mensagem encontrada. Digite o chat_id manualmente: ").strip()
        if not chat_id:
            raise ValueError("chat_id vazio.")
    path = notify.save_config(token, chat_id)
    print(f"[+] Credenciais salvas em {path} (permissão 600).")
    print("    Esse local funciona de qualquer pasta e com ou sem sudo.")
    notify.Telegram(token, chat_id).send_message(
        "✅ <b>Network Sentinel</b> configurado! Você receberá os alertas aqui.")
    print("[+] Mensagem de teste enviada. Confira o seu Telegram.")


def cmd_report(db, args):
    content = report.render(db, args.format)
    out = args.output or os.path.join("reports", f"report_{datetime.now():%Y%m%d_%H%M%S}.{args.format}")
    ensure_dir(os.path.dirname(os.path.abspath(out)))
    with open(out, "w", encoding="utf-8") as f:
        f.write(content)
    _chown_to_sudo_user(out)
    print(f"[+] Relatório salvo em {out}")
    if args.send:
        _send_report(db, out)


def cmd_demo(_db, args):
    from .demo import build_demo
    path = args.demo_db
    if os.path.exists(path):
        os.remove(path)
    ddb = Database(path)
    alerts = build_demo(ddb)
    print(f"[+] Demonstração criada em {path} ({len(ddb.list_devices())} dispositivos)\n")
    print_alerts(sorted(alerts, key=lambda a: ("critical high medium low info".split().index(a["severity"]), a["id"])))
    for fmt in ("html", "md"):
        out = os.path.join(args.out_dir, f"demo_report.{fmt}")
        ensure_dir(args.out_dir)
        with open(out, "w", encoding="utf-8") as f:
            f.write(report.render(ddb, fmt))
        print(f"[+] Relatório: {out}")


# ------------------------------------------------------------------ parser
def build_parser():
    p = argparse.ArgumentParser(prog="netsentinel",
                                description="Network Sentinel - vigia da sua rede doméstica.")
    p.add_argument("--version", action="version", version=f"netsentinel {__version__}")
    p.add_argument("--db", default=os.environ.get("NETSENTINEL_DB", "data/sentinel.db"),
                   help="caminho do banco SQLite (padrão: data/sentinel.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def scan_opts(sp):
        sp.add_argument("--subnet", help="CIDR alvo (padrão: sub-rede da sua interface)")
        sp.add_argument("--ports", action="store_true", help="varrer portas abertas (-sV)")
        sp.add_argument("--top-ports", type=int, default=100)
        sp.add_argument("--learn", action="store_true", help="marcar todos como confiáveis (baseline)")
        sp.add_argument("--absent-days", type=int, default=14)
        sp.add_argument("--notify", action="store_true", help="envia alertas novos pelo Telegram")
        sp.add_argument("--notify-level", choices=["critical", "high", "medium", "low"],
                        default="high", help="severidade mínima a notificar (padrão: high)")

    s = sub.add_parser("scan", help="varre a rede e analisa mudanças"); scan_opts(s); s.set_defaults(fn=cmd_scan)
    w = sub.add_parser("watch", help="varredura contínua"); scan_opts(w)
    w.add_argument("--interval", type=int, default=300)
    w.add_argument("--report-every", type=float, default=0, metavar="HORAS",
                   help="envia o relatório HTML pelo Telegram a cada N horas")
    w.add_argument("--serve", action="store_true", help="sobe o painel ao vivo junto com o monitoramento")
    w.set_defaults(fn=cmd_watch)
    for sp in (w,):
        sp.add_argument("--port", type=int, default=8000)
        sp.add_argument("--host", default="127.0.0.1")
        sp.add_argument("--refresh", type=int, default=10)
    v = sub.add_parser("serve", help="painel web ao vivo (relatório que se atualiza sozinho)")
    v.add_argument("--port", type=int, default=8000); v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--refresh", type=int, default=10, help="segundos entre atualizações")
    v.set_defaults(fn=cmd_serve)
    sub.add_parser("devices", help="lista o inventário").set_defaults(fn=cmd_devices)
    a = sub.add_parser("alerts", help="lista alertas"); a.add_argument("--all", action="store_true")
    a.set_defaults(fn=cmd_alerts)
    k = sub.add_parser("ack", help="marca alertas como vistos"); k.add_argument("id", nargs="?", type=int)
    k.add_argument("--all", action="store_true"); k.set_defaults(fn=cmd_ack)
    t = sub.add_parser("trust", help="marca dispositivo como confiável / define rótulo")
    t.add_argument("mac", nargs="?"); t.add_argument("--label"); t.add_argument("--all", action="store_true")
    t.add_argument("--untrust", action="store_true"); t.set_defaults(fn=cmd_trust)
    f = sub.add_parser("forget", help="remove um dispositivo do inventário (apaga o histórico dele)")
    f.add_argument("mac", nargs="?")
    f.add_argument("--all-untrusted", action="store_true",
                   help="remove todos os dispositivos marcados como desconhecidos")
    f.add_argument("-y", "--yes", action="store_true", help="não pedir confirmação")
    f.set_defaults(fn=cmd_forget)
    h = sub.add_parser("history", help="histórico de um dispositivo"); h.add_argument("mac")
    h.set_defaults(fn=cmd_history)
    c = sub.add_parser("capture", help="analisa tráfego com tshark (Wireshark)")
    c.add_argument("--iface"); c.add_argument("--duration", type=int, default=30)
    c.add_argument("--pcap", help="analisar arquivo .pcap salvo no Wireshark")
    c.add_argument("--max-mb", type=float, default=100.0)
    c.add_argument("--notify", action="store_true", help="envia alertas do tráfego pelo Telegram")
    c.add_argument("--notify-level", choices=["critical", "high", "medium", "low"],
                   default="high", help="severidade mínima a notificar (padrão: high)")
    c.add_argument("--loop", action="store_true",
                   help="fica vigiando sem parar, repetindo a captura em janelas de --duration")
    c.set_defaults(fn=cmd_capture)
    r = sub.add_parser("report", help="gera relatório"); r.add_argument("--format", choices=["html", "md"], default="html")
    r.add_argument("-o", "--output")
    r.add_argument("--send", action="store_true", help="envia o relatório pelo Telegram")
    r.set_defaults(fn=cmd_report)
    g = sub.add_parser("telegram", help="configura/testa as notificações do Telegram")
    g.add_argument("action", choices=["setup", "test"]); g.set_defaults(fn=cmd_telegram)
    d = sub.add_parser("demo", help="gera dados e relatório de demonstração (sem root)")
    d.add_argument("--demo-db", default="data/demo.db"); d.add_argument("--out-dir", default="reports")
    d.set_defaults(fn=cmd_demo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        db = Database(args.db) if args.cmd not in ("demo", "telegram") else None
        args.fn(db, args)
    except (ScanError, TelegramError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0
