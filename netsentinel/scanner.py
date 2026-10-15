"""Descoberta de dispositivos e portas via Nmap (saída XML, só biblioteca padrão)."""
import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional

from .models import Host, Port


class ScanError(RuntimeError):
    pass


@dataclass
class LocalInfo:
    iface: str
    ip: str
    mac: str
    network: str
    gateway: Optional[str]


def _sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def local_info() -> LocalInfo:
    """Descobre interface, IP, MAC, sub-rede e gateway da rota padrão."""
    m = re.search(r"default via (\S+) dev (\S+)", _sh(["ip", "-4", "route", "show", "default"]))
    if not m:
        raise ScanError("Rota padrão não encontrada. Você está conectado a uma rede?")
    gateway, iface = m.group(1), m.group(2)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)",
                  _sh(["ip", "-4", "-o", "addr", "show", "dev", iface]))
    if not m:
        raise ScanError(f"Interface {iface} sem endereço IPv4.")
    ifc = ipaddress.ip_interface(m.group(1))
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().lower()
    except OSError:
        mac = ""
    return LocalInfo(iface, str(ifc.ip), mac, str(ifc.network), gateway)


def _nmap(args: List[str], timeout: int) -> str:
    if not shutil.which("nmap"):
        raise ScanError("nmap não encontrado. Instale com: sudo apt install nmap")
    proc = subprocess.run(["nmap", *args, "-oX", "-"], capture_output=True,
                          text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise ScanError(proc.stderr.strip() or "Falha ao executar o nmap.")
    return proc.stdout


def parse_nmap_xml(xml_text: str) -> List[Host]:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr").lower(), a.get("vendor")
        if not ip:
            continue
        hn = h.find("hostnames/hostname")
        ports = None
        pe = h.find("ports")
        if pe is not None:
            ports = []
            for p in pe.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                name = svc.get("name", "") if svc is not None else ""
                ver = ""
                if svc is not None:
                    ver = " ".join(x for x in (svc.get("product"), svc.get("version")) if x)
                ports.append(Port(int(p.get("portid")), p.get("protocol", "tcp"), name, ver))
        hosts.append(Host(ip, mac, vendor, hn.get("name") if hn is not None else None, ports))
    return hosts


def discover(subnet: str, info: Optional[LocalInfo] = None) -> List[Host]:
    """Ping/ARP sweep (precisa de root para obter os MACs)."""
    hosts = parse_nmap_xml(_nmap(["-sn", "-T4", subnet], timeout=600))
    for h in hosts:
        h.ports = None
        if not h.mac and info and h.ip == info.ip and info.mac:  # o próprio host
            h.mac, h.vendor = info.mac, "(este computador)"
            import socket
            h.hostname = h.hostname or socket.gethostname()
    return hosts


def port_scan(hosts: List[Host], top_ports: int = 100) -> None:
    """Varre as portas mais comuns e anexa o resultado em cada Host."""
    ips = [h.ip for h in hosts]
    if not ips:
        return
    xml = _nmap(["-Pn", "-sV", "--version-light", "--top-ports", str(top_ports),
                 "--open", "-T4", *ips], timeout=3600)
    by_ip = {h.ip: h for h in parse_nmap_xml(xml)}
    for h in hosts:
        r = by_ip.get(h.ip)
        h.ports = r.ports if r and r.ports else []
