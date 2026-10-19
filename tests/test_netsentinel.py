import os
import tempfile
import unittest

from netsentinel.analyzer import is_randomized, process_scan
from netsentinel.capture import analyze_packets
from netsentinel.db import Database
from netsentinel.demo import build_demo
from netsentinel.models import Host
from netsentinel.report import render
from netsentinel.scanner import parse_nmap_xml

XML = """<nmaprun><host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Acme"/>
<hostnames><hostname name="tv.lan" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="23"><state state="open"/>
<service name="telnet"/></port></ports></host></nmaprun>"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.tmp, "t.db"))


class TestAnalyzer(Base):
    def kinds(self, alerts):
        return {a["kind"] for a in alerts}

    def test_baseline_has_no_new_device_alerts(self):
        r = process_scan(self.db, [Host("10.0.0.2", "aa:aa:aa:aa:aa:01")], "10.0.0.0/24", learn=True)
        self.assertEqual(r["alerts"], [])
        self.assertEqual(self.db.get_device("aa:aa:aa:aa:aa:01")["trusted"], 1)

    def test_new_device_and_ip_change(self):
        process_scan(self.db, [Host("10.0.0.2", "aa:aa:aa:aa:aa:01")], "n", learn=True,
                     ts="2026-01-01T10:00:00")
        r = process_scan(self.db, [Host("10.0.0.9", "aa:aa:aa:aa:aa:01"),
                                   Host("10.0.0.3", "bb:bb:bb:bb:bb:02")], "n",
                         ts="2026-01-02T10:00:00")
        self.assertEqual(self.kinds(r["alerts"]), {"IP_CHANGED", "NEW_DEVICE"})

    def test_gateway_change_is_critical(self):
        process_scan(self.db, [Host("10.0.0.1", "aa:aa:aa:aa:aa:01")], "n", "10.0.0.1", learn=True)
        r = process_scan(self.db, [Host("10.0.0.1", "cc:cc:cc:cc:cc:03")], "n", "10.0.0.1")
        self.assertIn("critical", {a["severity"] for a in r["alerts"]})

    def test_ports_baseline_then_new_port(self):
        from netsentinel.models import Port
        h = lambda ports: [Host("10.0.0.2", "aa:aa:aa:aa:aa:01", ports=ports)]
        process_scan(self.db, h([Port(80)]), "n", learn=True, ts="2026-01-01T10:00:00")
        r = process_scan(self.db, h([Port(80), Port(8080), Port(23, service="telnet")]), "n",
                         ts="2026-01-02T10:00:00")
        self.assertEqual(self.kinds(r["alerts"]), {"NEW_PORT", "RISKY_PORT"})

    def test_randomized_mac(self):
        self.assertTrue(is_randomized("02:5b:9e:ab:cd:ef"))
        self.assertFalse(is_randomized("a4:2b:b0:11:22:33"))

    def test_forget_device_removes_everything(self):
        from netsentinel.models import Port
        mac = "aa:aa:aa:aa:aa:01"
        process_scan(self.db, [Host("10.0.0.2", mac, ports=[Port(80)])], "n", learn=True,
                     ts="2026-01-01T10:00:00")
        process_scan(self.db, [Host("10.0.0.3", mac, ports=[Port(80)])], "n",
                     ts="2026-01-02T10:00:00")  # gera histórico de IP e um alerta IP_CHANGED
        self.assertIsNotNone(self.db.get_device(mac))
        self.assertTrue(self.db.ip_history(mac))
        self.assertTrue(self.db.open_ports(mac))
        self.assertTrue(self.db.list_alerts(only_open=False))

        self.assertTrue(self.db.forget_device(mac))
        self.assertIsNone(self.db.get_device(mac))
        self.assertEqual(self.db.ip_history(mac), [])
        self.assertEqual(self.db.open_ports(mac), [])
        self.assertEqual(self.db.sighting_count(mac), 0)
        self.assertEqual([a for a in self.db.list_alerts(only_open=False) if a["mac"] == mac], [])

    def test_forget_unknown_mac_returns_false(self):
        self.assertFalse(self.db.forget_device("ff:ff:ff:ff:ff:ff"))


class TestParsingCaptureReport(Base):
    def test_parse_nmap(self):
        h = parse_nmap_xml(XML)[0]
        self.assertEqual((h.ip, h.mac, h.vendor, h.hostname), ("192.168.1.5", "aa:bb:cc:00:11:22", "Acme", "tv.lan"))
        self.assertEqual(h.ports[0].port, 23)

    def test_arp_spoofing_detected(self):
        pk = [{"eth_src": "aa:aa:aa:aa:aa:01", "length": 60, "arp_ip": "10.0.0.1", "arp_mac": "aa:aa:aa:aa:aa:01", "arp_op": "2"},
              {"eth_src": "bb:bb:bb:bb:bb:02", "length": 60, "arp_ip": "10.0.0.1", "arp_mac": "bb:bb:bb:bb:bb:02", "arp_op": "2"}]
        r = analyze_packets(self.db, pk, gateway_ip="10.0.0.1")
        kinds = {(a["kind"], a["severity"]) for a in r["alerts"]}
        self.assertIn(("ARP_SPOOFING", "critical"), kinds)
        self.assertIn(("UNKNOWN_TRAFFIC", "high"), kinds)

    def test_demo_and_reports(self):
        alerts = build_demo(self.db)
        kinds = {a["kind"] for a in alerts}
        self.assertTrue({"GATEWAY_CHANGED", "NEW_DEVICE", "RISKY_PORT", "NEW_PORT", "IP_CHANGED",
                         "HOSTNAME_CHANGED", "DEVICE_RETURNED"} <= kinds, kinds)
        html, md = render(self.db, "html"), render(self.db, "md")
        self.assertIn("GATEWAY_CHANGED", html)
        self.assertIn("## Inventário", md)


if __name__ == "__main__":
    unittest.main()


class TestServer(Base):
    def test_live_server(self):
        import json
        import urllib.request
        from netsentinel.server import serve
        build_demo(self.db)
        srv = serve(self.db.path, "127.0.0.1", 0, 5, block=False)
        port = srv.server_address[1]
        try:
            html = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
            self.assertIn("ao vivo", html)
            self.assertIn("GATEWAY_CHANGED", html)
            data = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/api.json"))
            self.assertEqual(len(data["devices"]), 11)
            # muda o banco e vê a mudança no próximo acesso, sem reiniciar o servidor
            self.db.update_device("e8:db:84:12:90:ab", label="ESP da garagem")
            html2 = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
            self.assertIn("ESP da garagem", html2)
        finally:
            srv.shutdown()
