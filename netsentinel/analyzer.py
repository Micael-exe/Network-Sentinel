"""Motor de regras: compara cada varredura com o histórico e gera alertas."""
from datetime import datetime, timedelta
from typing import List, Optional

from .db import Database, now
from .models import Host

# Portas que merecem atenção quando abertas em dispositivos domésticos.
RISKY_PORTS = {
    21: "FTP (sem criptografia)", 23: "Telnet (sem criptografia)", 69: "TFTP",
    135: "MSRPC", 139: "NetBIOS", 445: "SMB", 1900: "UPnP", 2323: "Telnet alternativo",
    3389: "RDP (área de trabalho remota)", 5555: "ADB (Android Debug Bridge)",
    5900: "VNC", 7547: "TR-069 (gestão remota de roteador)", 8291: "Winbox (MikroTik)",
}


def is_randomized(mac: str) -> bool:
    """Bit 'localmente administrado': MACs privados de celulares modernos."""
    return bool(int(mac.split(":")[0], 16) & 0b10)


def _port_label(p) -> str:
    extra = f" - {p.service}" if p.service else ""
    extra += f" {p.version}" if p.version else ""
    return f"{p.port}/{p.proto}{extra}"


def process_scan(db: Database, hosts: List[Host], subnet: str,
                 gateway_ip: Optional[str] = None, learn: bool = False,
                 ts: Optional[str] = None, absent_days: int = 14) -> dict:
    """Aplica as regras a uma varredura e persiste inventário, histórico e alertas.

    learn=True marca tudo o que foi visto como confiável (baseline inicial).
    """
    ts = ts or now()
    ts_dt = datetime.fromisoformat(ts)
    created: List[dict] = []

    def alert(sev, kind, mac, ip, msg):
        a = db.add_alert(ts, sev, kind, mac, ip, msg)
        if a:
            created.append(a)

    groups = {}
    skipped = 0
    for h in hosts:
        if h.mac:
            groups.setdefault(h.mac, []).append(h)
        else:
            skipped += 1

    scan_id = db.add_scan(ts, subnet)
    prev_gw = db.gateway_mac()
    new_devices = 0

    for mac, hs in groups.items():
        h = next((x for x in hs if gateway_ip and x.ip == gateway_ip), hs[0])
        ips = sorted({x.ip for x in hs})
        is_gw = bool(gateway_ip) and gateway_ip in ips
        rnd = is_randomized(mac)
        dev = db.get_device(mac)
        who = h.hostname or h.vendor or "sem identificação"

        # --- 1) novo dispositivo ou atualização de um conhecido ----------
        if dev is None:
            new_devices += 1
            db.insert_device(mac, h.ip, h.hostname, h.vendor, learn, rnd, ts)
            if not learn:
                note = (" MAC randomizado (típico de celulares com 'endereço Wi-Fi privado')."
                        if rnd else "")
                alert("high", "NEW_DEVICE", mac, h.ip,
                      f"Dispositivo desconhecido entrou na rede: {who} "
                      f"[{h.vendor or 'fabricante desconhecido'}].{note}")
        else:
            if dev["ip"] and dev["ip"] != h.ip:
                alert("low", "IP_CHANGED", mac, h.ip,
                      f"{dev['label'] or who} mudou de IP: {dev['ip']} -> {h.ip}")
            if dev["hostname"] and h.hostname and dev["hostname"] != h.hostname:
                alert("medium", "HOSTNAME_CHANGED", mac, h.ip,
                      f"Hostname mudou: '{dev['hostname']}' -> '{h.hostname}' "
                      f"(mesmo MAC; verifique se o equipamento foi reconfigurado).")
            try:
                gap = ts_dt - datetime.fromisoformat(dev["last_seen"])
                if gap > timedelta(days=absent_days):
                    alert("low", "DEVICE_RETURNED", mac, h.ip,
                          f"{dev['label'] or who} reapareceu após {gap.days} dias ausente.")
            except ValueError:
                pass
            db.update_device(mac, ip=h.ip, last_seen=ts,
                             hostname=h.hostname or dev["hostname"],
                             vendor=h.vendor or dev["vendor"])

        db.touch_ip(mac, h.ip, ts)
        db.add_sighting(scan_id, mac, h.ip, ts)

        # --- 2) gateway: possível ARP spoofing / roteador trocado --------
        if is_gw:
            if prev_gw and prev_gw != mac:
                old = db.get_device(prev_gw) or {}
                alert("critical", "GATEWAY_CHANGED", mac, gateway_ip,
                      f"O MAC do gateway {gateway_ip} mudou de {prev_gw} "
                      f"({old.get('vendor') or '?'}) para {mac} ({h.vendor or '?'}). "
                      f"Possível ARP spoofing / man-in-the-middle ou roteador substituído.")
            db.set_gateway(mac)

        # --- 3) um MAC respondendo por muitos IPs -------------------------
        if len(ips) >= 3 and not is_gw:
            alert("medium", "MAC_MULTI_IP", mac, h.ip,
                  f"O MAC {mac} responde por {len(ips)} IPs ({', '.join(ips)}). "
                  f"Pode indicar ARP spoofing ou proxy-ARP.")

        # --- 4) portas ----------------------------------------------------
        if h.ports is not None:
            baseline = not (dev and dev["ports_scanned"])
            known = db.get_ports(mac)
            seen = set()
            for p in h.ports:
                key = (p.port, p.proto)
                seen.add(key)
                label = _port_label(p)
                is_new = key not in known or known[key]["state"] != "open"
                if is_new:
                    if p.port in RISKY_PORTS:
                        alert("high", "RISKY_PORT", mac, h.ip,
                              f"Porta de risco aberta em {who}: {label} - {RISKY_PORTS[p.port]}")
                    elif not baseline:
                        alert("medium", "NEW_PORT", mac, h.ip,
                              f"Nova porta aberta em {who}: {label}")
                db.upsert_port(mac, p, ts)
            for (port, proto), row in known.items():
                if (port, proto) not in seen and row["state"] == "open":
                    db.close_port(mac, port, proto, ts)
            db.update_device(mac, ports_scanned=1)

    db.finish_scan(scan_id, len(groups), new_devices, len(created))
    return {"scan_id": scan_id, "ts": ts, "hosts": len(groups),
            "new_devices": new_devices, "alerts": created, "skipped_no_mac": skipped}
