"""Dados sintéticos para demonstrar a ferramenta sem precisar de root/nmap."""
from datetime import datetime, timedelta

from .analyzer import process_scan
from .db import Database
from .models import Host, Port

SUBNET = "192.168.1.0/24"
GW = "192.168.1.1"


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _baseline():
    return [
        Host(GW, "a4:2b:b0:11:22:33", "TP-Link", "roteador.lan", [Port(80, "tcp", "http"), Port(443, "tcp", "https")]),
        Host("192.168.1.10", "3c:22:fb:aa:bb:01", "Apple", "macbook-ana", []),
        Host("192.168.1.11", "dc:a6:32:12:34:56", "Raspberry Pi", "raspberrypi", [Port(22, "tcp", "ssh", "OpenSSH 9.2")]),
        Host("192.168.1.20", "f4:f5:d8:55:66:77", "Google", "chromecast", []),
        Host("192.168.1.30", "00:17:88:0a:0b:0c", "Philips Lighting", "hue-bridge", [Port(80, "tcp", "http")]),
        Host("192.168.1.50", "00:1b:a9:44:55:66", "Brother Industries", "impressora", [Port(631, "tcp", "ipp")]),
        Host("192.168.1.60", "8c:79:f5:77:88:99", "Samsung", "smart-tv", []),
        Host("192.168.1.70", "c0:56:e3:de:ad:01", "Hikvision", "camera-sala", [Port(80, "tcp", "http"), Port(554, "tcp", "rtsp")]),
    ]


def build_demo(db: Database) -> list:
    """Cria 3 varreduras (baseline, intermediária, atual) e devolve os alertas gerados."""
    t_now = datetime.now()
    base = _baseline()

    # 1) baseline há 20 dias: tudo vira "confiável"
    process_scan(db, base, SUBNET, GW, learn=True, ts=_iso(t_now - timedelta(days=20)))
    for mac, label in [("3c:22:fb:aa:bb:01", "MacBook da Ana"), ("dc:a6:32:12:34:56", "Raspberry Pi"),
                       ("c0:56:e3:de:ad:01", "Câmera da sala")]:
        db.update_device(mac, label=label)

    # 2) varredura intermediária: a TV está desligada
    mid = [h for h in _baseline() if h.mac != "8c:79:f5:77:88:99"]
    process_scan(db, mid, SUBNET, GW, ts=_iso(t_now - timedelta(days=2)))

    # 3) varredura atual, com anomalias plantadas
    cur = _baseline()
    for h in cur:
        if h.mac == "3c:22:fb:aa:bb:01":                       # mudou de IP
            h.ip = "192.168.1.15"
        elif h.mac == "dc:a6:32:12:34:56":                     # hostname diferente
            h.hostname = "kali-unknown"
        elif h.mac == "c0:56:e3:de:ad:01":                     # câmera com Telnet + porta nova
            h.ports += [Port(23, "tcp", "telnet"), Port(8080, "tcp", "http-proxy")]
        elif h.mac == "a4:2b:b0:11:22:33":                     # MAC do gateway foi trocado
            h.mac, h.vendor, h.hostname = "00:0c:29:de:ad:be", "VMware, Inc.", None
    cur += [
        Host("192.168.1.99", "02:5b:9e:ab:cd:ef", None, None, []),                 # MAC privado
        Host("192.168.1.101", "e8:db:84:12:90:ab", "Espressif", "esp32-desconhecido", [Port(80, "tcp", "http")]),
    ]
    result = process_scan(db, cur, SUBNET, GW, ts=_iso(t_now))
    return result["alerts"]
