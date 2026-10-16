import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from netsentinel import notify
from netsentinel.notify import Telegram, TelegramError

GOOD = "123456:GOODTOKEN"
BAD = "999:BADTOKEN"


class Fake(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Fake.calls.append((self.path, self.headers.get("Content-Type", ""), body))
        code, resp = 200, {"ok": True, "result": {"message_id": 1}}
        if "BADTOKEN" in self.path:
            code, resp = 401, {"ok": False, "description": "Unauthorized"}
        elif self.path.endswith("/getMe"):
            resp = {"ok": True, "result": {"username": "sentinel_bot"}}
        elif self.path.endswith("/getUpdates"):
            chat = {"id": 777, "first_name": "Micael", "type": "private"}
            resp = {"ok": True, "result": [{"message": {"chat": chat}}, {"message": {"chat": chat}}]}
        raw = json.dumps(resp).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


ALERTS = [
    {"id": 1, "severity": "low", "kind": "IP_CHANGED", "ip": "10.0.0.5", "message": "mudou de IP"},
    {"id": 2, "severity": "critical", "kind": "GATEWAY_CHANGED", "ip": "10.0.0.1",
     "message": "MAC do gateway mudou <script>"},
    {"id": 3, "severity": "high", "kind": "NEW_DEVICE", "ip": "10.0.0.9", "message": "novo aparelho"},
]


class TestTelegram(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Fake.calls.clear()

    def test_filter_and_format(self):
        high = notify.filter_alerts(ALERTS, "high")
        self.assertEqual({a["id"] for a in high}, {2, 3})
        text = notify.format_alerts(sorted(high, key=lambda a: a["severity"] != "critical"))
        self.assertIn("🔴", text)
        self.assertIn("&lt;script&gt;", text)          # HTML escapado
        self.assertLess(text.index("GATEWAY_CHANGED"), text.index("NEW_DEVICE"))

    def test_notify_alerts_sends_one_grouped_message(self):
        n = notify.notify_alerts((GOOD, "42"), ALERTS, "high", api_base=self.base)
        self.assertEqual(n, 2)
        self.assertEqual(len(Fake.calls), 1)
        path, ctype, body = Fake.calls[0]
        self.assertEqual(path, f"/bot{GOOD}/sendMessage")
        payload = json.loads(body)
        self.assertEqual((payload["chat_id"], payload["parse_mode"]), ("42", "HTML"))

    def test_nothing_to_send_below_level(self):
        low_only = [ALERTS[0]]
        self.assertEqual(notify.notify_alerts((GOOD, "42"), low_only, "high", api_base=self.base), 0)
        self.assertEqual(Fake.calls, [])

    def test_send_document_multipart(self):
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
            f.write("<h1>relatorio</h1>")
        try:
            Telegram(GOOD, "42", self.base).send_document(f.name, "legenda teste")
        finally:
            os.unlink(f.name)
        path, ctype, body = Fake.calls[0]
        self.assertTrue(path.endswith("/sendDocument"))
        self.assertIn("multipart/form-data; boundary=", ctype)
        self.assertIn(b"<h1>relatorio</h1>", body)
        self.assertIn(b"legenda teste", body)
        self.assertIn(b'name="chat_id"', body)

    def test_chat_discovery_dedupes(self):
        tg = Telegram(GOOD, "", self.base)
        self.assertEqual(tg.get_me()["username"], "sentinel_bot")
        self.assertEqual(tg.get_chat_ids(), [(777, "Micael", "private")])

    def test_error_never_leaks_token(self):
        with self.assertRaises(TelegramError) as ctx:
            Telegram(BAD, "1", self.base).send_message("oi")
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("BADTOKEN", str(ctx.exception))

    def test_connection_failure_is_telegram_error(self):
        with self.assertRaises(TelegramError) as ctx:
            Telegram(GOOD, "1", "http://127.0.0.1:1", timeout=2).send_message("oi")
        self.assertNotIn("GOODTOKEN", str(ctx.exception))

    def test_config_roundtrip_and_permissions(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, ".env")
        saved = notify.save_config("1:abc", "55", path)
        self.assertEqual(oct(os.stat(saved).st_mode & 0o777), "0o600")
        os.environ.pop("TELEGRAM_TOKEN", None)
        os.environ.pop("TELEGRAM_CHAT_ID", None)
        self.assertEqual(notify.load_config(path), ("1:abc", "55"))
        self.assertIsNone(notify.load_config(os.path.join(d, "nao_existe")))


if __name__ == "__main__":
    unittest.main()
