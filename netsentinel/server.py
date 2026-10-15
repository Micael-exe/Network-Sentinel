"""Servidor HTTP local: gera o relatório a partir do banco a cada acesso (tempo real)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import report
from .db import Database


def _handler(db_path: str, refresh: int):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            if path not in ("/", "/index.html", "/report.md", "/api.json"):
                self.send_error(404)
                return
            db = Database(db_path)
            try:
                if path == "/report.md":
                    body, ctype = report.render(db, "md").encode(), "text/markdown; charset=utf-8"
                elif path == "/api.json":
                    body = json.dumps(report.collect(db), default=str, ensure_ascii=False).encode()
                    ctype = "application/json; charset=utf-8"
                else:
                    body, ctype = report.render(db, "html", refresh).encode(), "text/html; charset=utf-8"
            finally:
                db.conn.close()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silencia o log por requisição
            pass
    return Handler


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8000, refresh: int = 10,
          block: bool = True) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _handler(db_path, refresh))
    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Servidor encerrado.")
        finally:
            server.server_close()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
