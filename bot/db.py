"""
db.py — sqlite-слой r-bot.

Хранит: клиентов, привязки TG→idNN, invite-коды, заявки на привязку,
пул VLESS-ссылок, привязки пула к роутерам, состояние роутеров и
историю изменений, audit действий.

Формат БД: один файл, WAL для конкурентных чтений.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    tg_id       INTEGER PRIMARY KEY,
    username    TEXT,
    first_name  TEXT,
    role        TEXT NOT NULL CHECK(role IN ('admin','client')),
    note        TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS bindings (
    tg_id       INTEGER NOT NULL,
    router_id   TEXT NOT NULL,
    added_at    TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (tg_id, router_id),
    FOREIGN KEY (tg_id) REFERENCES clients(tg_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_bindings_tg ON bindings(tg_id);
CREATE INDEX IF NOT EXISTS idx_bindings_router ON bindings(router_id);

CREATE TABLE IF NOT EXISTS invite_codes (
    code        TEXT PRIMARY KEY,
    router_id   TEXT NOT NULL,
    created_by  INTEGER NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    used_by     INTEGER,
    used_at     TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id       INTEGER NOT NULL,
    username    TEXT,
    router_id   TEXT NOT NULL,
    message     TEXT,
    status      TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','approved','rejected')),
    created_at  TEXT DEFAULT (datetime('now')),
    decided_at  TEXT,
    decided_by  INTEGER
);

CREATE TABLE IF NOT EXISTS vless_pool (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    remark      TEXT,
    host        TEXT,
    vless_url   TEXT UNIQUE NOT NULL,
    added_by    INTEGER NOT NULL,
    added_at    TEXT DEFAULT (datetime('now'))
);

-- Если для роутера НЕТ записей — клиент видит весь пул.
-- Если есть хоть одна — клиент видит только перечисленные.
CREATE TABLE IF NOT EXISTS router_vless_allow (
    router_id   TEXT NOT NULL,
    vless_id    INTEGER NOT NULL,
    PRIMARY KEY (router_id, vless_id),
    FOREIGN KEY (vless_id) REFERENCES vless_pool(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS router_state (
    router_id        TEXT PRIMARY KEY,
    label            TEXT,
    online           INTEGER NOT NULL DEFAULT 0,
    podkop_status    TEXT,
    uptime           TEXT,
    wan_ip           TEXT,
    active_vless     TEXT,
    last_poll_at     TEXT,
    last_online_at   TEXT,
    last_offline_at  TEXT
);

CREATE TABLE IF NOT EXISTS router_state_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id   TEXT NOT NULL,
    event       TEXT NOT NULL,
    details     TEXT,
    at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_history_at ON router_state_history(at);
CREATE INDEX IF NOT EXISTS idx_history_router ON router_state_history(router_id);

CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id       INTEGER,
    username    TEXT,
    router_id   TEXT,
    action      TEXT NOT NULL,
    args        TEXT,
    result      TEXT,
    at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_tg ON audit(tg_id, at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);

CREATE TABLE IF NOT EXISTS rate_limits (
    tg_id       INTEGER NOT NULL,
    action      TEXT NOT NULL,
    day         TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tg_id, action, day)
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT
);
"""


class DB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path),
            timeout=10,
            check_same_thread=False,
            isolation_level=None,   # autocommit
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    # --- низкоуровневое ---
    @contextmanager
    def tx(self):
        cur = self._conn.cursor()
        cur.execute("BEGIN")
        try:
            yield cur
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    def q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self._conn.execute(sql, params))

    def q1(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        row = self._conn.execute(sql, params).fetchone()
        return row

    def ex(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)

    def close(self):
        self._conn.close()

    # --- clients ---
    def upsert_client(
        self,
        tg_id: int,
        username: str | None,
        first_name: str | None,
        role: str = "client",
        note: str | None = None,
    ):
        existing = self.q1("SELECT role FROM clients WHERE tg_id=?", (tg_id,))
        if existing:
            self.ex(
                "UPDATE clients SET username=?, first_name=?, last_seen=datetime('now') WHERE tg_id=?",
                (username, first_name, tg_id),
            )
        else:
            self.ex(
                "INSERT INTO clients(tg_id, username, first_name, role, note) VALUES (?,?,?,?,?)",
                (tg_id, username, first_name, role, note),
            )

    def set_role(self, tg_id: int, role: str):
        self.ex("UPDATE clients SET role=? WHERE tg_id=?", (role, tg_id))

    def get_client(self, tg_id: int) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM clients WHERE tg_id=?", (tg_id,))

    def all_clients(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM clients ORDER BY role DESC, created_at")

    def set_admin(self, tg_id: int, username: str | None = None):
        existing = self.get_client(tg_id)
        if existing:
            self.set_role(tg_id, "admin")
        else:
            self.upsert_client(tg_id, username, None, role="admin")

    def touch_seen(self, tg_id: int):
        self.ex(
            "UPDATE clients SET last_seen=datetime('now') WHERE tg_id=?",
            (tg_id,),
        )

    def delete_client(self, tg_id: int):
        self.ex("DELETE FROM clients WHERE tg_id=?", (tg_id,))

    # --- bindings ---
    def bind(self, tg_id: int, router_id: str):
        self.ex(
            "INSERT OR IGNORE INTO bindings(tg_id, router_id) VALUES (?,?)",
            (tg_id, router_id),
        )

    def unbind(self, tg_id: int, router_id: str):
        self.ex(
            "DELETE FROM bindings WHERE tg_id=? AND router_id=?",
            (tg_id, router_id),
        )

    def client_routers(self, tg_id: int) -> list[str]:
        return [
            r["router_id"]
            for r in self.q("SELECT router_id FROM bindings WHERE tg_id=? ORDER BY router_id", (tg_id,))
        ]

    def router_clients(self, router_id: str) -> list[sqlite3.Row]:
        return self.q(
            """SELECT c.* FROM clients c
               JOIN bindings b ON b.tg_id=c.tg_id
               WHERE b.router_id=?""",
            (router_id,),
        )

    # --- invite codes ---
    def create_invite(self, router_id: str, created_by: int, ttl_hours: int = 24) -> str:
        code = f"{router_id.upper()}-{secrets.token_urlsafe(3).upper().replace('_','X').replace('-','Y')[:4]}"
        expires = (datetime.utcnow() + timedelta(hours=ttl_hours)).strftime("%Y-%m-%d %H:%M:%S")
        self.ex(
            "INSERT INTO invite_codes(code, router_id, created_by, expires_at) VALUES (?,?,?,?)",
            (code, router_id, created_by, expires),
        )
        return code

    def use_invite(self, code: str, tg_id: int) -> Optional[str]:
        row = self.q1(
            "SELECT router_id, expires_at, used_by FROM invite_codes WHERE code=?",
            (code,),
        )
        if not row:
            return None
        if row["used_by"]:
            return None
        if row["expires_at"] < datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"):
            return None
        self.ex(
            "UPDATE invite_codes SET used_by=?, used_at=datetime('now') WHERE code=?",
            (tg_id, code),
        )
        return row["router_id"]

    def active_invites(self) -> list[sqlite3.Row]:
        return self.q(
            """SELECT * FROM invite_codes
               WHERE used_by IS NULL AND expires_at > datetime('now')
               ORDER BY created_at DESC"""
        )

    # --- requests ---
    def create_request(self, tg_id: int, username: str | None, router_id: str, message: str) -> int:
        cur = self.ex(
            "INSERT INTO requests(tg_id, username, router_id, message) VALUES (?,?,?,?)",
            (tg_id, username, router_id, message),
        )
        return cur.lastrowid or 0

    def pending_requests(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM requests WHERE status='pending' ORDER BY created_at")

    def get_request(self, rid: int) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM requests WHERE id=?", (rid,))

    def decide_request(self, rid: int, status: str, by_tg: int):
        self.ex(
            "UPDATE requests SET status=?, decided_at=datetime('now'), decided_by=? WHERE id=?",
            (status, by_tg, rid),
        )

    # --- vless pool ---
    def add_vless(self, vless_url: str, remark: str, host: str, added_by: int) -> int:
        cur = self.ex(
            """INSERT OR IGNORE INTO vless_pool(vless_url, remark, host, added_by)
               VALUES (?,?,?,?)""",
            (vless_url, remark, host, added_by),
        )
        if cur.lastrowid:
            return cur.lastrowid
        existing = self.q1("SELECT id FROM vless_pool WHERE vless_url=?", (vless_url,))
        return existing["id"] if existing else 0

    def delete_vless(self, vid: int):
        self.ex("DELETE FROM vless_pool WHERE id=?", (vid,))

    def all_vless(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM vless_pool ORDER BY remark")

    def vless_by_id(self, vid: int) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM vless_pool WHERE id=?", (vid,))

    def vless_for_router(self, router_id: str) -> list[sqlite3.Row]:
        """Что видит клиент на данном idNN.

        Если есть явные привязки — только они.
        Если нет — весь пул.
        """
        allow = self.q(
            "SELECT vless_id FROM router_vless_allow WHERE router_id=?",
            (router_id,),
        )
        if allow:
            ids = [r["vless_id"] for r in allow]
            placeholders = ",".join("?" * len(ids))
            return self.q(
                f"SELECT * FROM vless_pool WHERE id IN ({placeholders}) ORDER BY remark",
                tuple(ids),
            )
        return self.all_vless()

    def set_router_allow(self, router_id: str, vless_ids: list[int]):
        with self.tx() as cur:
            cur.execute("DELETE FROM router_vless_allow WHERE router_id=?", (router_id,))
            for vid in vless_ids:
                cur.execute(
                    "INSERT OR IGNORE INTO router_vless_allow(router_id, vless_id) VALUES (?,?)",
                    (router_id, vid),
                )

    # --- router state ---
    def update_state(
        self,
        router_id: str,
        label: str | None,
        online: bool,
        podkop_status: str | None,
        uptime: str | None,
        wan_ip: str | None,
        active_vless: str | None,
    ):
        prev = self.q1(
            "SELECT online, podkop_status, active_vless FROM router_state WHERE router_id=?",
            (router_id,),
        )
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.ex(
            """INSERT INTO router_state(router_id, label, online, podkop_status, uptime,
                                        wan_ip, active_vless, last_poll_at,
                                        last_online_at, last_offline_at)
               VALUES (?,?,?,?,?,?,?,?,
                       CASE WHEN ?=1 THEN ? ELSE NULL END,
                       CASE WHEN ?=0 THEN ? ELSE NULL END)
               ON CONFLICT(router_id) DO UPDATE SET
                 label=excluded.label,
                 online=excluded.online,
                 podkop_status=excluded.podkop_status,
                 uptime=excluded.uptime,
                 wan_ip=excluded.wan_ip,
                 active_vless=excluded.active_vless,
                 last_poll_at=excluded.last_poll_at,
                 last_online_at=CASE WHEN ?=1 THEN ? ELSE router_state.last_online_at END,
                 last_offline_at=CASE WHEN ?=0 THEN ? ELSE router_state.last_offline_at END
            """,
            (
                router_id, label, int(online), podkop_status, uptime,
                wan_ip, active_vless, now,
                int(online), now,
                int(online), now,
                int(online), now,
                int(online), now,
            ),
        )
        # --- history events ---
        if prev:
            if bool(prev["online"]) != online:
                self.ex(
                    "INSERT INTO router_state_history(router_id, event, details) VALUES (?,?,?)",
                    (router_id, "online" if online else "offline", None),
                )
            if online and prev["podkop_status"] != podkop_status:
                self.ex(
                    "INSERT INTO router_state_history(router_id, event, details) VALUES (?,?,?)",
                    (router_id, f"podkop_{podkop_status}", None),
                )
            if active_vless and prev["active_vless"] != active_vless:
                self.ex(
                    "INSERT INTO router_state_history(router_id, event, details) VALUES (?,?,?)",
                    (router_id, "vless_change", active_vless[:200]),
                )

    def get_state(self, router_id: str) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM router_state WHERE router_id=?", (router_id,))

    def all_states(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM router_state ORDER BY router_id")

    def history_since(self, since_iso: str) -> list[sqlite3.Row]:
        return self.q(
            "SELECT * FROM router_state_history WHERE at >= ? ORDER BY at",
            (since_iso,),
        )

    def delete_router_state(self, router_id: str):
        self.ex("DELETE FROM router_state WHERE router_id=?", (router_id,))
        self.ex("DELETE FROM router_vless_allow WHERE router_id=?", (router_id,))

    # --- audit ---
    def audit(
        self,
        tg_id: int | None,
        username: str | None,
        router_id: str | None,
        action: str,
        args: str | None = None,
        result: str | None = None,
    ):
        self.ex(
            """INSERT INTO audit(tg_id, username, router_id, action, args, result)
               VALUES (?,?,?,?,?,?)""",
            (tg_id, username, router_id, action, args, result),
        )

    def audit_recent(self, limit: int = 50, tg_id: int | None = None) -> list[sqlite3.Row]:
        if tg_id:
            return self.q(
                "SELECT * FROM audit WHERE tg_id=? ORDER BY at DESC LIMIT ?",
                (tg_id, limit),
            )
        return self.q("SELECT * FROM audit ORDER BY at DESC LIMIT ?", (limit,))

    # --- rate limits ---
    def rate_check_and_inc(self, tg_id: int, action: str, limit: int) -> bool:
        """True если операция разрешена (и счётчик увеличен), False если лимит исчерпан."""
        day = datetime.utcnow().strftime("%Y-%m-%d")
        row = self.q1(
            "SELECT count FROM rate_limits WHERE tg_id=? AND action=? AND day=?",
            (tg_id, action, day),
        )
        current = row["count"] if row else 0
        if current >= limit:
            return False
        if row:
            self.ex(
                "UPDATE rate_limits SET count=count+1 WHERE tg_id=? AND action=? AND day=?",
                (tg_id, action, day),
            )
        else:
            self.ex(
                "INSERT INTO rate_limits(tg_id, action, day, count) VALUES (?,?,?,1)",
                (tg_id, action, day),
            )
        return True

    # --- settings ---
    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.q1("SELECT value FROM settings WHERE key=?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]

    def set_setting(self, key: str, value: Any):
        self.ex(
            "INSERT INTO settings(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
