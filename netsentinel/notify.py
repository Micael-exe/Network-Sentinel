"""Notificações via Telegram (só biblioteca padrão: urllib)."""
import html
import json
import mimetypes
import os
import urllib.error
import urllib.request
import uuid
from typing import List, Optional, Tuple

from .db import SEVERITY_ORDER

API_BASE = "https://api.telegram.org"
ENV_FILE = ".env"
MAX_ALERTS_PER_MESSAGE = 10
EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
LABEL = {"critical": "CRÍTICO", "high": "ALTO", "medium": "MÉDIO", "low": "BAIXO", "info": "INFO"}


class TelegramError(RuntimeError):
    pass


# ------------------------------------------------------------- configuração
def parse_env_file(path: str) -> dict:
    values = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip("'\"")
    return values


def load_config(path: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Lê (token, chat_id) das variáveis de ambiente ou do arquivo .env."""
    path = path or os.environ.get("NETSENTINEL_ENV", ENV_FILE)
    cfg = parse_env_file(path) if os.path.isfile(path) else {}
    token = os.environ.get("TELEGRAM_TOKEN") or cfg.get("TELEGRAM_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID") or cfg.get("TELEGRAM_CHAT_ID")
    return (token, chat) if token and chat else None


def save_config(token: str, chat_id: str, path: Optional[str] = None) -> str:
    """Grava token/chat_id no .env com permissão 600 (só o dono lê)."""
    path = path or os.environ.get("NETSENTINEL_ENV", ENV_FILE)
    values = parse_env_file(path) if os.path.isfile(path) else {}
    values.update({"TELEGRAM_TOKEN": token, "TELEGRAM_CHAT_ID": str(chat_id)})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("# Segredos do Network Sentinel - NUNCA envie este arquivo ao GitHub\n")
        for k, v in values.items():
            f.write(f"{k}={v}\n")
    os.chmod(path, 0o600)
    return path


# ------------------------------------------------------------ cliente HTTP
class Telegram:
    def __init__(self, token: str, chat_id: str, api_base: str = API_BASE, timeout: int = 15):
        self.token, self.chat_id = token, str(chat_id)
        self.api_base, self.timeout = api_base.rstrip("/"), timeout

    def _clean(self, text: str) -> str:  # nunca vazar o token em mensagens de erro
        return text.replace(self.token, "***")

    def _call(self, method: str, body: bytes, content_type: str):
        req = urllib.request.Request(f"{self.api_base}/bot{self.token}/{method}", data=body,
                                     headers={"Content-Type": content_type}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            try:
                desc = json.load(exc).get("description", "")
            except (ValueError, OSError):
                desc = ""
            raise TelegramError(self._clean(f"HTTP {exc.code} {desc}".strip())) from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise TelegramError(self._clean(f"sem conexão com o Telegram ({exc})")) from None
        if not payload.get("ok"):
            raise TelegramError(self._clean(payload.get("description", "erro desconhecido")))
        return payload["result"]

    def _json(self, method: str, data: dict):
        return self._call(method, json.dumps(data).encode(), "application/json")

    def get_me(self) -> dict:
        return self._json("getMe", {})

    def get_chat_ids(self) -> List[Tuple[int, str, str]]:
        """Chats que já falaram com o bot: [(id, nome, tipo)]."""
        seen, out = set(), []
        for upd in self._json("getUpdates", {"limit": 50}):
            msg = upd.get("message") or upd.get("edited_message") or {}
            chat = msg.get("chat")
            if not chat or chat["id"] in seen:
                continue
            seen.add(chat["id"])
            name = (" ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
                    or chat.get("title") or chat.get("username") or "?")
            out.append((chat["id"], name, chat.get("type", "?")))
        return out

    def send_message(self, text: str):
        return self._json("sendMessage", {"chat_id": self.chat_id, "text": text[:4000],
                                          "parse_mode": "HTML",
                                          "disable_web_page_preview": True})

    def send_document(self, path: str, caption: str = ""):
        boundary = uuid.uuid4().hex
        parts = []

        def field(name, value):
            parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                          f'\r\n\r\n{value}\r\n').encode())
        field("chat_id", self.chat_id)
        if caption:
            field("caption", caption[:1000])
        with open(path, "rb") as f:
            data = f.read()
        fname = os.path.basename(path)
        ctype = mimetypes.guess_type(fname)[0] or "application/octet-stream"
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                      f'filename="{fname}"\r\nContent-Type: {ctype}\r\n\r\n').encode()
                     + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self._call("sendDocument", b"".join(parts),
                          f"multipart/form-data; boundary={boundary}")


# --------------------------------------------------------------- mensagens
def filter_alerts(alerts: List[dict], min_level: str = "high") -> List[dict]:
    limit = SEVERITY_ORDER[min_level]
    return [a for a in alerts if SEVERITY_ORDER.get(a["severity"], 9) <= limit]


def format_alerts(alerts: List[dict]) -> str:
    n = len(alerts)
    lines = [f"🛡️ <b>Network Sentinel</b> — {n} alerta(s) novo(s)", ""]
    for a in alerts[:MAX_ALERTS_PER_MESSAGE]:
        lines.append(f"{EMOJI.get(a['severity'], '⚪')} <b>{LABEL.get(a['severity'], '?')}</b> · "
                     f"<code>{html.escape(a['kind'])}</code>")
        lines.append(html.escape(a["message"][:400]))
        if a.get("ip"):
            lines.append(f"IP: <code>{html.escape(a['ip'])}</code>")
        lines.append("")
    if n > MAX_ALERTS_PER_MESSAGE:
        lines.append(f"… e mais {n - MAX_ALERTS_PER_MESSAGE} alerta(s). "
                     f"Veja todos com: netsentinel alerts")
    return "\n".join(lines).strip()


def notify_alerts(cfg: Tuple[str, str], alerts: List[dict], min_level: str = "high",
                  api_base: str = API_BASE) -> int:
    """Envia UMA mensagem agrupando os alertas relevantes. Devolve quantos foram enviados."""
    chosen = sorted(filter_alerts(alerts, min_level), key=lambda a: SEVERITY_ORDER[a["severity"]])
    if not chosen:
        return 0
    Telegram(*cfg, api_base=api_base).send_message(format_alerts(chosen))
    return len(chosen)
