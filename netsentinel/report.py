"""Geração de relatórios (HTML autocontido e Markdown)."""
from collections import Counter
from html import escape as e

from .db import Database, now

SEV_LABEL = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO",
             "low": "BAIXO", "info": "INFO"}


def collect(db: Database) -> dict:
    devices = db.list_devices()
    for d in devices:
        d["ports"] = db.open_ports(d["mac"])
        d["history"] = db.ip_history(d["mac"])
        d["seen"] = db.sighting_count(d["mac"])
    alerts = db.list_alerts(only_open=True)
    scans = db.list_scans(10)
    return {"generated": now(), "devices": devices, "alerts": alerts, "scans": scans,
            "subnet": scans[0]["subnet"] if scans else "-",
            "last_scan": scans[0]["ts"] if scans else "nunca",
            "sev": Counter(a["severity"] for a in alerts)}


def _ports_txt(d):
    return ", ".join(str(p["port"]) for p in d["ports"]) or "-"


def _name(d):
    return d["label"] or d["hostname"] or "-"


# ---------------------------------------------------------------- Markdown
def render_md(data: dict) -> str:
    devs, alerts = data["devices"], data["alerts"]
    trusted = sum(1 for d in devs if d["trusted"])
    L = ["# Network Sentinel - Relatório", "",
         f"Gerado em **{data['generated']}** | Sub-rede **{data['subnet']}** | "
         f"Última varredura **{data['last_scan']}**", "",
         f"- Dispositivos: **{len(devs)}** ({trusted} confiáveis, {len(devs)-trusted} desconhecidos)",
         f"- Alertas abertos: **{len(alerts)}** "
         f"(críticos: {data['sev']['critical']}, altos: {data['sev']['high']}, "
         f"médios: {data['sev']['medium']})", "", "## Alertas", ""]
    if alerts:
        L += ["| Sev. | Tipo | Quando | Mensagem |", "|---|---|---|---|"]
        L += [f"| {SEV_LABEL[a['severity']]} | {a['kind']} | {a['ts']} | "
              f"{a['message'].replace('|', '/')} |" for a in alerts]
    else:
        L.append("Nenhum alerta aberto.")
    L += ["", "## Inventário de dispositivos", "",
          "| Status | IP | MAC | Fabricante | Nome | Portas | Último visto |",
          "|---|---|---|---|---|---|---|"]
    for d in devs:
        L.append(f"| {'confiável' if d['trusted'] else '**DESCONHECIDO**'} | {d['ip']} | "
                 f"`{d['mac']}` | {d['vendor'] or '-'} | {_name(d)} | {_ports_txt(d)} | "
                 f"{d['last_seen']} |")
    L += ["", "## Histórico de varreduras", "", "| # | Data | Hosts | Novos | Alertas |",
          "|---|---|---|---|---|"]
    L += [f"| {s['id']} | {s['ts']} | {s['hosts']} | {s['new_devices']} | {s['alerts']} |"
          for s in data["scans"]]
    return "\n".join(L) + "\n"


# -------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--mut:#667085;--line:#e4e7ec;--acc:#2563eb;
--critical:#b42318;--high:#d92d20;--medium:#b54708;--low:#175cd3;--info:#667085}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--fg:#e6e9ef;
--mut:#98a2b3;--line:#2a313c;--acc:#6ea8fe;--critical:#ff6b60;--high:#f97066;
--medium:#fdb022;--low:#7cb2ff;--info:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px}
main{max-width:1100px;margin:0 auto}h1{margin:0 0 4px;font-size:24px}
h2{margin:32px 0 10px;font-size:17px}.sub{color:var(--mut);margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px}.card span{color:var(--mut);font-size:13px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}code{font:13px ui-monospace,Menlo,monospace}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;
border:1px solid currentColor;white-space:nowrap}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}
.low{color:var(--low)}.info{color:var(--info)}.ok{color:#12b76a}.unk{color:var(--high)}
.live{color:#12b76a;font-size:13px;margin:-12px 0 16px}.live.off{color:var(--high)}
.muted{color:var(--mut)}footer{margin:28px 0 0;color:var(--mut);font-size:12px}
"""


def render_html(data: dict, refresh: int = 0) -> str:
    devs, alerts = data["devices"], data["alerts"]
    trusted = sum(1 for d in devs if d["trusted"])
    sev = data["sev"]

    cards = "".join(f'<div class="card"><b>{v}</b><span>{e(k)}</span></div>' for k, v in [
        ("Dispositivos", len(devs)), ("Confiáveis", trusted),
        ("Desconhecidos", len(devs) - trusted), ("Alertas abertos", len(alerts)),
        ("Críticos / altos", f"{sev['critical']} / {sev['high']}")])

    if alerts:
        rows = "".join(
            f'<tr><td><span class="b {a["severity"]}">{SEV_LABEL[a["severity"]]}</span></td>'
            f'<td><code>{e(a["kind"])}</code></td><td class="muted">{e(a["ts"])}</td>'
            f'<td>{e(a["ip"] or "-")}</td><td>{e(a["message"])}</td></tr>' for a in alerts)
        alert_html = (f'<div class="wrap"><table><tr><th>Severidade</th><th>Tipo</th>'
                      f'<th>Quando</th><th>IP</th><th>Detalhe</th></tr>{rows}</table></div>')
    else:
        alert_html = '<p class="muted">Nenhum alerta aberto.</p>'

    drows = ""
    for d in devs:
        status = ('<span class="b ok">confiável</span>' if d["trusted"]
                  else '<span class="b unk">desconhecido</span>')
        tags = ""
        if d["is_gateway"]:
            tags += ' <span class="b info">gateway</span>'
        if d["randomized"]:
            tags += ' <span class="b info">MAC privado</span>'
        drows += (f'<tr><td>{status}</td><td>{e(d["ip"] or "-")}</td><td><code>{e(d["mac"])}</code></td>'
                  f'<td>{e(d["vendor"] or "-")}</td><td>{e(_name(d))}{tags}</td>'
                  f'<td>{e(_ports_txt(d))}</td><td class="muted">{d["seen"]}</td>'
                  f'<td class="muted">{e(d["first_seen"])}</td><td class="muted">{e(d["last_seen"])}</td></tr>')

    hist = ""
    for d in devs:
        if len(d["history"]) > 1:
            trail = " &rarr; ".join(f'<code>{e(h["ip"])}</code>' for h in d["history"])
            hist += f'<tr><td>{e(_name(d))} <code>{e(d["mac"])}</code></td><td>{trail}</td></tr>'
    hist_html = (f'<div class="wrap"><table><tr><th>Dispositivo</th><th>IPs ao longo do tempo</th></tr>'
                 f'{hist}</table></div>') if hist else '<p class="muted">Nenhuma mudança de IP registrada.</p>'

    srows = "".join(f'<tr><td>{s["id"]}</td><td>{e(s["ts"])}</td><td>{s["hosts"]}</td>'
                    f'<td>{s["new_devices"]}</td><td>{s["alerts"]}</td></tr>' for s in data["scans"])

    live = script = ""
    if refresh:
        live = (f'<p class="live" id="live">&#9679; ao vivo &middot; atualiza a cada '
                f'{refresh}s</p>')
        script = ("<script>setInterval(async()=>{try{const r=await fetch(location.pathname,"
                  "{cache:'no-store'});const d=new DOMParser().parseFromString(await r.text(),"
                  "'text/html');document.querySelector('main').innerHTML="
                  "d.querySelector('main').innerHTML}catch(e){const l=document.getElementById("
                  "'live');if(l){l.className='live off';l.textContent='sem conexão com o servidor'}}},"
                  f"{refresh * 1000});</script>")
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Sentinel - Relatório</title><style>{CSS}</style></head><body><main>
<h1>Network Sentinel</h1>
<p class="sub">Relatório gerado em {e(data["generated"])} &middot; sub-rede {e(data["subnet"])} &middot; última varredura {e(data["last_scan"])}</p>
{live}<div class="cards">{cards}</div>
<h2>Alertas e possíveis anomalias</h2>{alert_html}
<h2>Inventário de dispositivos</h2>
<div class="wrap"><table><tr><th>Status</th><th>IP</th><th>MAC</th><th>Fabricante</th><th>Nome</th>
<th>Portas abertas</th><th>Vistos</th><th>Primeira vez</th><th>Última vez</th></tr>{drows}</table></div>
<h2>Histórico de IPs</h2>{hist_html}
<h2>Últimas varreduras</h2>
<div class="wrap"><table><tr><th>#</th><th>Data</th><th>Hosts</th><th>Novos</th><th>Alertas</th></tr>{srows}</table></div>
<footer>Network Sentinel &middot; use apenas em redes que você administra.</footer>
</main>{script}</body></html>"""


def render(db: Database, fmt: str = "html", refresh: int = 0) -> str:
    data = collect(db)
    return render_md(data) if fmt == "md" else render_html(data, refresh)
