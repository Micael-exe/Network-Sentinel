"""Análise de tráfego com tshark (linha de comando do Wireshark)."""
import shutil
import subprocess
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from .db import Database, now
from .scanner import ScanError

FIELDS = ["eth.src", "ip.src", "ip.dst", "frame.len", "arp.opcode",
          "arp.src.hw_mac", "arp.src.proto_ipv4"]
KEYS = ["eth_src", "ip_src", "ip_dst", "length", "arp_op", "arp_mac", "arp_ip"]


def run_tshark(iface: Optional[str] = None, duration: int = 30,
               pcap: Optional[str] = None) -> List[Dict]:
    """Captura ao vivo (precisa de root) ou lê um .pcap salvo pelo Wireshark."""
    if not shutil.which("tshark"):
        raise ScanError("tshark não encontrado. Instale com: sudo apt install tshark")
    cmd = ["tshark", "-l", "-n", "-T", "fields", "-E", "separator=/t"]
    for f in FIELDS:
        cmd += ["-e", f]
    if pcap:
        cmd += ["-r", pcap]
        timeout = 3600
    else:
        if not iface:
            raise ScanError("Informe a interface com --iface (ex.: eth0, wlan0).")
        cmd += ["-i", iface, "-a", f"duration:{duration}"]
        timeout = duration + 60
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise ScanError(proc.stderr.strip()[-300:] or "Falha ao executar o tshark.")
    packets = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(KEYS) - len(parts))
        p = {k: v.split(",")[0].strip() for k, v in zip(KEYS, parts)}
        try:
            p["length"] = int(p["length"] or 0)
        except ValueError:
            p["length"] = 0
        packets.append(p)
    return packets


def _is_multicast(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except ValueError:
        return True


def analyze_packets(db: Database, packets: List[Dict], gateway_ip: Optional[str] = None,
                    max_mb: float = 100.0, flood_threshold: int = 100,
                    ts: Optional[str] = None) -> dict:
    """Detecta ARP spoofing, ARP flood, tráfego de MAC desconhecido e picos de volume."""
    ts = ts or now()
    devices = {d["mac"]: d for d in db.list_devices()}
    bytes_by_mac, arp_replies = Counter(), Counter()
    arp_claims = defaultdict(set)
    for p in packets:
        mac = p.get("eth_src", "").lower()
        if mac:
            bytes_by_mac[mac] += p.get("length", 0)
        a_ip, a_mac = p.get("arp_ip", ""), p.get("arp_mac", "").lower()
        if a_ip and a_mac and a_ip != "0.0.0.0":
            arp_claims[a_ip].add(a_mac)
        if p.get("arp_op") == "2" and a_mac:
            arp_replies[a_mac] += 1

    created = []

    def alert(sev, kind, mac, ip, msg):
        if db.is_allowed(mac, kind):
            return
        a = db.add_alert(ts, sev, kind, mac, ip, msg)
        if a:
            created.append(a)

    for ip, macs in sorted(arp_claims.items()):
        if len(macs) > 1:
            sev = "critical" if ip == gateway_ip else "high"
            alert(sev, "ARP_SPOOFING", None, ip,
                  f"O IP {ip} foi anunciado via ARP por {len(macs)} MACs diferentes: "
                  f"{', '.join(sorted(macs))}. Forte indício de ARP spoofing.")
    for mac, n in arp_replies.items():
        if n >= flood_threshold:
            alert("high", "ARP_FLOOD", mac, None,
                  f"{n} respostas ARP vindas de {mac} na janela de captura (possível envenenamento).")
    for mac, total in bytes_by_mac.items():
        if _is_multicast(mac):
            continue
        dev = devices.get(mac)
        if dev is None:
            alert("high", "UNKNOWN_TRAFFIC", mac, None,
                  f"Tráfego de MAC fora do inventário: {mac}. Rode 'scan' para identificá-lo.")
        elif total > max_mb * 1_000_000:
            sev = "medium" if dev["trusted"] else "high"
            alert(sev, "TRAFFIC_SPIKE", mac, dev["ip"],
                  f"{dev['label'] or dev['hostname'] or mac} gerou {total/1e6:.1f} MB "
                  f"na janela de captura (limite: {max_mb:g} MB).")

    talkers = []
    for mac, total in bytes_by_mac.most_common(10):
        dev = devices.get(mac, {})
        talkers.append({"mac": mac, "bytes": total,
                        "name": dev.get("label") or dev.get("hostname") or "(desconhecido)"})
    return {"packets": len(packets), "talkers": talkers, "alerts": created}
