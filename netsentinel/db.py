"""Camada de persistência (SQLite): inventário, histórico, alertas e varreduras."""
import ipaddress
import os
import re
import sqlite3
from datetime import datetime, timedelta

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, label TEXT,
    trusted INTEGER NOT NULL DEFAULT 0, is_gateway INTEGER NOT NULL DEFAULT 0,
    randomized INTEGER NOT NULL DEFAULT 0, ports_scanned INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL, ip TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    mac TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL,
    service TEXT, version TEXT, state TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    PRIMARY KEY (mac, port, proto)
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, subnet TEXT,
    hosts INTEGER DEFAULT 0, new_devices INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sightings (
    scan_id INTEGER NOT NULL, mac TEXT NOT NULL, ip TEXT, ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, severity TEXT NOT NULL,
    kind TEXT NOT NULL, mac TEXT, ip TEXT, message TEXT NOT NULL,
    ack INTEGER NOT NULL DEFAULT 0
);
"""

DEVICE_FIELDS = {"ip", "hostname", "vendor", "label", "trusted", "is_gateway",
                 "ports_scanned", "last_seen"}


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValueError(f"MAC inválido: {mac}")
    return mac


def _chown_to_sudo_user(path: str) -> None:
    """Se rodando via sudo, devolve a posse do arquivo/pasta ao usuário real."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(path, int(uid), int(gid or uid))
        except OSError:
            pass


def ensure_dir(path: str) -> None:
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        _chown_to_sudo_user(path)


class Database:
    def __init__(self, path: str):
        self.path = path
        ensure_dir(os.path.dirname(os.path.abspath(path)))
        is_new = not os.path.exists(path)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        if is_new:
            _chown_to_sudo_user(path)

    # -- helpers ---------------------------------------------------------
    def q(self, sql, args=()):
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.conn.execute(sql, args).fetchone()
        return dict(r) if r else None

    def x(self, sql, args=()):
        cur = self.conn.execute(sql, args)
        self.conn.commit()
        return cur

    # -- dispositivos ----------------------------------------------------
    def get_device(self, mac):
        return self.one("SELECT * FROM devices WHERE mac=?", (mac,))

    def list_devices(self):
        rows = self.q("SELECT * FROM devices")

        def key(r):
            try:
                return (r["trusted"], int(ipaddress.ip_address(r["ip"])))
            except (ValueError, TypeError):
                return (r["trusted"], 0)
        return sorted(rows, key=key)

    def insert_device(self, mac, ip, hostname, vendor, trusted, randomized, ts,
                      is_gateway=False):
        self.x("INSERT INTO devices(mac,ip,hostname,vendor,trusted,randomized,"
               "is_gateway,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
               (mac, ip, hostname, vendor, int(trusted), int(randomized),
                int(is_gateway), ts, ts))

    def update_device(self, mac, **fields):
        bad = set(fields) - DEVICE_FIELDS
        if bad:
            raise ValueError(f"Campos inválidos: {bad}")
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        self.x(f"UPDATE devices SET {sets} WHERE mac=?", (*fields.values(), mac))

    def gateway_mac(self):
        r = self.one("SELECT mac FROM devices WHERE is_gateway=1 "
                     "ORDER BY last_seen DESC LIMIT 1")
        return r["mac"] if r else None

    def set_gateway(self, mac):
        self.conn.execute("UPDATE devices SET is_gateway=0")
        self.conn.execute("UPDATE devices SET is_gateway=1 WHERE mac=?", (mac,))
        self.conn.commit()

    # -- histórico de IP / presença -------------------------------------
    def touch_ip(self, mac, ip, ts):
        row = self.one("SELECT id FROM ip_history WHERE mac=? AND ip=?", (mac, ip))
        if row:
            self.x("UPDATE ip_history SET last_seen=? WHERE id=?", (ts, row["id"]))
        else:
            self.x("INSERT INTO ip_history(mac,ip,first_seen,last_seen) "
                   "VALUES(?,?,?,?)", (mac, ip, ts, ts))

    def ip_history(self, mac):
        return self.q("SELECT ip, first_seen, last_seen FROM ip_history "
                      "WHERE mac=? ORDER BY first_seen", (mac,))

    def add_sighting(self, scan_id, mac, ip, ts):
        self.x("INSERT INTO sightings VALUES(?,?,?,?)", (scan_id, mac, ip, ts))

    def sighting_count(self, mac):
        return self.one("SELECT COUNT(*) AS n FROM sightings WHERE mac=?", (mac,))["n"]

    # -- portas ----------------------------------------------------------
    def get_ports(self, mac):
        return {(r["port"], r["proto"]): r for r in
                self.q("SELECT * FROM ports WHERE mac=?", (mac,))}

    def open_ports(self, mac):
        return self.q("SELECT port, proto, service, version FROM ports "
                      "WHERE mac=? AND state='open' ORDER BY port", (mac,))

    def upsert_port(self, mac, p, ts):
        self.x("INSERT INTO ports(mac,port,proto,service,version,state,first_seen,last_seen) "
               "VALUES(?,?,?,?,?,'open',?,?) ON CONFLICT(mac,port,proto) DO UPDATE SET "
               "service=excluded.service, version=excluded.version, state='open', "
               "last_seen=excluded.last_seen",
               (mac, p.port, p.proto, p.service, p.version, ts, ts))

    def close_port(self, mac, port, proto, ts):
        self.x("UPDATE ports SET state='closed', last_seen=? WHERE mac=? AND port=? "
               "AND proto=?", (ts, mac, port, proto))

    # -- varreduras ------------------------------------------------------
    def add_scan(self, ts, subnet):
        return self.x("INSERT INTO scans(ts,subnet) VALUES(?,?)", (ts, subnet)).lastrowid

    def finish_scan(self, scan_id, hosts, new_devices, alerts):
        self.x("UPDATE scans SET hosts=?, new_devices=?, alerts=? WHERE id=?",
               (hosts, new_devices, alerts, scan_id))

    def list_scans(self, limit=10):
        return self.q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    # -- alertas ---------------------------------------------------------
    def add_alert(self, ts, severity, kind, mac, ip, message, dedupe_hours=6):
        cutoff = (datetime.fromisoformat(ts) - timedelta(hours=dedupe_hours)
                  ).isoformat(timespec="seconds")
        dup = self.one("SELECT id FROM alerts WHERE kind=? AND IFNULL(mac,'')=? "
                       "AND message=? AND ts>=?", (kind, mac or "", message, cutoff))
        if dup:
            return None
        cur = self.x("INSERT INTO alerts(ts,severity,kind,mac,ip,message) "
                     "VALUES(?,?,?,?,?,?)", (ts, severity, kind, mac, ip, message))
        return {"id": cur.lastrowid, "ts": ts, "severity": severity, "kind": kind,
                "mac": mac, "ip": ip, "message": message, "ack": 0}

    def list_alerts(self, only_open=True, limit=None):
        sql = "SELECT * FROM alerts" + (" WHERE ack=0" if only_open else "")
        rows = self.q(sql)
        rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), -r["id"]))
        return rows[:limit] if limit else rows

    def ack(self, alert_id=None):
        if alert_id is None:
            return self.x("UPDATE alerts SET ack=1 WHERE ack=0").rowcount
        return self.x("UPDATE alerts SET ack=1 WHERE id=?", (alert_id,)).rowcount
