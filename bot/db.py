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
    last_offline_at  TEXT,
    -- Stage 1 / Пункт 1+3+A5 additions:
    sing_running        INTEGER,   -- 0/1, pgrep sing-box
    nft_table           INTEGER,   -- 0/1, PodkopTable в nftables
    local_ip            TEXT,      -- IP от провайдера (yandex.ru/internet)
    egress_ip           TEXT,      -- IP на выходе из VLESS (ifconfig.co)
    egress_country      TEXT,      -- 'Germany'
    egress_country_iso  TEXT,      -- 'DE'
    egress_city         TEXT,
    egress_asn_org      TEXT,
    hw_model            TEXT,      -- 'Xiaomi Redmi AC2100'
    openwrt_version     TEXT,
    podkop_version      TEXT,
    singbox_version     TEXT,
    -- Stage 2 / A1+A2+пункт 7:
    lifecycle_status    TEXT,      -- NULL/'online'/'offline'/'transit'/'maintenance'
    custom_vless_url    TEXT,      -- если задан, роутер выходит из ротации
    in_pool             INTEGER,   -- 0/1; 0 ⇒ в ротации не участвует
    wifi_ssid           TEXT,      -- последний снапшот SSID (для отображения)
    wifi_encryption     TEXT,      -- последний снапшот шифрования
    wifi_updated_at     TEXT       -- когда снапшот сделан
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

-- Stage 3 / Клиент пкт 8: буфер pending-правок списка доменов.
-- На сессию на клиента-роутер — единый буфер. Переживает рестарт бота.
CREATE TABLE IF NOT EXISTS pending_routing (
    tg_id        INTEGER NOT NULL,
    router_id    TEXT NOT NULL,
    added_json   TEXT,              -- JSON list of added domains
    removed_json TEXT,              -- JSON list of removed domains
    started_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (tg_id, router_id)
);

-- Stage 3 / Клиент пкт 2: логи от клиентов, присланные админу.
-- Хранятся 30 дней (job cleanup) + файл в paths.client_logs.
CREATE TABLE IF NOT EXISTS client_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id          INTEGER NOT NULL,
    username       TEXT,
    router_id      TEXT NOT NULL,
    log_path       TEXT,              -- абсолютный путь к файлу
    preview        TEXT,              -- первые 5 строк для списка
    read_by_admin  INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_client_logs_created ON client_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_client_logs_router  ON client_logs(router_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_client_logs_unread  ON client_logs(read_by_admin, created_at DESC);

-- Stage 3 / Клиент пкт 7 (доп): история WiFi-правок (без паролей).
CREATE TABLE IF NOT EXISTS wifi_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id    TEXT NOT NULL,
    ssid_before  TEXT,
    ssid_after   TEXT,
    tg_id        INTEGER,
    changed_at   TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_wifi_history_router ON wifi_history(router_id, changed_at DESC);

-- beta07 / F6: whitelist доступа к боту.
-- В whitelist попадают: админы (через bootstrap), все владельцы роутеров
-- (через миграцию из bindings), а также вручную приглашённые пользователи
-- (команда /allow или кнопка «➕ Приглашённый» в админ-меню).
-- Все остальные при /start получают вежливый отказ; админ НЕ получает
-- никаких уведомлений (защита от спама случайными визитёрами).
CREATE TABLE IF NOT EXISTS allowed_users (
    tg_id      INTEGER PRIMARY KEY,
    username   TEXT,
    added_by   INTEGER,                  -- tg_id админа; NULL для авто-миграции
    added_at   INTEGER NOT NULL,         -- unix-timestamp
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_allowed_username ON allowed_users(username);

-- beta07 / F5: история спидтестов.
-- Двухканальный замер (intl Cloudflare + RU Yandex mirror) с ping.
-- router_id хранится как строка id07 чтобы не привязываться к int-PK
-- (другие таблицы тоже используют строковые router_id).
CREATE TABLE IF NOT EXISTS speedtests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id     TEXT    NOT NULL,
    ts            INTEGER NOT NULL,        -- unix epoch UTC
    triggered_by  TEXT,                    -- "admin:<username>" / "client:<tg_id>"
    intl_mbps     REAL,
    ru_mbps       REAL,
    intl_ping_ms  REAL,
    ru_ping_ms    REAL,
    intl_http     INTEGER,
    ru_http       INTEGER,
    verdict       TEXT                     -- "OK" | "WARN" | "FAIL" | "ERROR"
);
CREATE INDEX IF NOT EXISTS idx_speedtests_router_ts
    ON speedtests(router_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_speedtests_ts
    ON speedtests(ts);
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
        self._migrate()

    # =========================================================================
    # Stage 1 migration — добавляем колонки в router_state на существующих БД.
    # SQLite ALTER TABLE ADD COLUMN идемпотентен только если колонки нет —
    # проверяем PRAGMA table_info перед каждым ALTER.
    # =========================================================================
    def _migrate(self) -> None:
        cur = self._conn.execute("PRAGMA table_info(router_state)")
        existing = {row[1] for row in cur.fetchall()}
        new_cols = [
            # Stage 1
            ("sing_running",       "INTEGER"),
            ("nft_table",          "INTEGER"),
            ("local_ip",           "TEXT"),
            ("egress_ip",          "TEXT"),
            ("egress_country",     "TEXT"),
            ("egress_country_iso", "TEXT"),
            ("egress_city",        "TEXT"),
            ("egress_asn_org",     "TEXT"),
            ("hw_model",           "TEXT"),
            ("openwrt_version",    "TEXT"),
            ("podkop_version",     "TEXT"),
            ("singbox_version",    "TEXT"),
            # Stage 2 (A1, A2, клиентский пункт 7)
            ("lifecycle_status",   "TEXT"),
            ("custom_vless_url",   "TEXT"),
            ("in_pool",            "INTEGER"),
            ("wifi_ssid",          "TEXT"),
            ("wifi_encryption",    "TEXT"),
            ("wifi_updated_at",    "TEXT"),
        ]
        for name, decl in new_cols:
            if name not in existing:
                self._conn.execute(
                    f"ALTER TABLE router_state ADD COLUMN {name} {decl}"
                )

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

    def client_by_username(self, username: str) -> Optional[sqlite3.Row]:
        """Stage 2 / A9: поиск клиента по telegram @username (без учёта регистра)."""
        if not username:
            return None
        u = username.strip().lstrip("@")
        if not u:
            return None
        return self.q1(
            "SELECT * FROM clients WHERE LOWER(username)=LOWER(?) LIMIT 1",
            (u,),
        )

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
        # Stage 1 additions: дефолты None, чтобы старые вызовы не сломались.
        sing_running: bool | None = None,
        nft_table: bool | None = None,
        local_ip: str | None = None,
        egress_ip: str | None = None,
        egress_country: str | None = None,
        egress_country_iso: str | None = None,
        egress_city: str | None = None,
        egress_asn_org: str | None = None,
        hw_model: str | None = None,
        openwrt_version: str | None = None,
        podkop_version: str | None = None,
        singbox_version: str | None = None,
    ):
        prev = self.q1(
            "SELECT online, podkop_status, active_vless FROM router_state WHERE router_id=?",
            (router_id,),
        )
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        # Преобразуем bool|None → int|None для SQLite.
        sing_int = None if sing_running is None else int(bool(sing_running))
        nft_int = None if nft_table is None else int(bool(nft_table))
        self.ex(
            """INSERT INTO router_state(router_id, label, online, podkop_status, uptime,
                                        wan_ip, active_vless, last_poll_at,
                                        last_online_at, last_offline_at,
                                        sing_running, nft_table, local_ip, egress_ip,
                                        egress_country, egress_country_iso, egress_city,
                                        egress_asn_org, hw_model, openwrt_version,
                                        podkop_version, singbox_version)
               VALUES (?,?,?,?,?,?,?,?,
                       CASE WHEN ?=1 THEN ? ELSE NULL END,
                       CASE WHEN ?=0 THEN ? ELSE NULL END,
                       ?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET
                 label=excluded.label,
                 online=excluded.online,
                 podkop_status=excluded.podkop_status,
                 uptime=excluded.uptime,
                 wan_ip=excluded.wan_ip,
                 active_vless=excluded.active_vless,
                 last_poll_at=excluded.last_poll_at,
                 last_online_at=CASE WHEN ?=1 THEN ? ELSE router_state.last_online_at END,
                 last_offline_at=CASE WHEN ?=0 THEN ? ELSE router_state.last_offline_at END,
                 -- Stage 1 поля: для offline-ветки оставляем старые значения,
                 -- для online — перезаписываем (даже если None — это корректно
                 -- для случая когда внешний IP-проб не отработал).
                 sing_running       = COALESCE(excluded.sing_running,       router_state.sing_running),
                 nft_table          = COALESCE(excluded.nft_table,          router_state.nft_table),
                 local_ip           = COALESCE(excluded.local_ip,           router_state.local_ip),
                 egress_ip          = COALESCE(excluded.egress_ip,          router_state.egress_ip),
                 egress_country     = COALESCE(excluded.egress_country,     router_state.egress_country),
                 egress_country_iso = COALESCE(excluded.egress_country_iso, router_state.egress_country_iso),
                 egress_city        = COALESCE(excluded.egress_city,        router_state.egress_city),
                 egress_asn_org     = COALESCE(excluded.egress_asn_org,     router_state.egress_asn_org),
                 hw_model           = COALESCE(excluded.hw_model,           router_state.hw_model),
                 openwrt_version    = COALESCE(excluded.openwrt_version,    router_state.openwrt_version),
                 podkop_version     = COALESCE(excluded.podkop_version,     router_state.podkop_version),
                 singbox_version    = COALESCE(excluded.singbox_version,    router_state.singbox_version)
            """,
            (
                router_id, label, int(online), podkop_status, uptime,
                wan_ip, active_vless, now,
                int(online), now,
                int(online), now,
                sing_int, nft_int, local_ip, egress_ip,
                egress_country, egress_country_iso, egress_city,
                egress_asn_org, hw_model, openwrt_version,
                podkop_version, singbox_version,
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

    # --- Stage 2: lifecycle / custom VLESS / WiFi snapshot helpers ---
    # Все три апдейта используют UPSERT, чтобы запись router_state создавалась
    # автоматически даже если poll ещё не успел её сделать (например, после
    # ручного добавления роутера в конфиг).

    def set_lifecycle(self, router_id: str, status: str | None) -> None:
        """status ∈ {'online','offline','transit','maintenance', None}.
        None = «как у polling» (использовать online/offline по результатам опроса).
        Кнопки админа выставляют 'transit' и 'maintenance'; «✅ Активировать» и
        «▶ Снять техработы» сбрасывают в None."""
        self.ex(
            """INSERT INTO router_state(router_id, lifecycle_status)
               VALUES (?, ?)
               ON CONFLICT(router_id) DO UPDATE SET lifecycle_status=excluded.lifecycle_status""",
            (router_id, status),
        )

    def set_custom_vless(self, router_id: str, url: str | None) -> None:
        """url=None ⇒ кастом сброшен, in_pool=1 (роутер возвращается в ротацию).
        url=str ⇒ in_pool=0, кастом активен."""
        in_pool = 1 if url is None else 0
        self.ex(
            """INSERT INTO router_state(router_id, custom_vless_url, in_pool)
               VALUES (?, ?, ?)
               ON CONFLICT(router_id) DO UPDATE SET
                 custom_vless_url=excluded.custom_vless_url,
                 in_pool=excluded.in_pool""",
            (router_id, url, in_pool),
        )

    def set_wifi_snapshot(self, router_id: str, ssid: str | None,
                          encryption: str | None) -> None:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.ex(
            """INSERT INTO router_state(router_id, wifi_ssid, wifi_encryption, wifi_updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(router_id) DO UPDATE SET
                 wifi_ssid=excluded.wifi_ssid,
                 wifi_encryption=excluded.wifi_encryption,
                 wifi_updated_at=excluded.wifi_updated_at""",
            (router_id, ssid, encryption, now),
        )

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

    # Stage 3 / A7: audit по роутеру, пагинация, retention.
    def audit_by_router(self, router_id: str, offset: int = 0,
                        limit: int = 30) -> list[sqlite3.Row]:
        return self.q(
            "SELECT * FROM audit WHERE router_id=? ORDER BY at DESC LIMIT ? OFFSET ?",
            (router_id, limit, offset),
        )

    def audit_count_by_router(self, router_id: str) -> int:
        row = self.q1(
            "SELECT COUNT(*) AS c FROM audit WHERE router_id=?",
            (router_id,),
        )
        return int(row["c"]) if row else 0

    def audit_all_by_router(self, router_id: str) -> list[sqlite3.Row]:
        """Вся история (для CSV-экспорта). Ограничиваем, чтобы не увести bot в OOM."""
        return self.q(
            "SELECT * FROM audit WHERE router_id=? ORDER BY at DESC LIMIT 10000",
            (router_id,),
        )

    def audit_retention_cleanup(self, days: int = 90) -> int:
        """Stage 3 / A7: удалить audit-записи старше N дней. Возвращает сколько удалено."""
        cur = self.ex(
            "DELETE FROM audit WHERE at < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        return cur.rowcount or 0

    # =========================================================================
    # Stage 3 / Клиент пкт 8: pending_routing (буфер правок списка доменов).
    # =========================================================================
    def pending_routing_get(self, tg_id: int, router_id: str) -> Optional[sqlite3.Row]:
        return self.q1(
            "SELECT * FROM pending_routing WHERE tg_id=? AND router_id=?",
            (tg_id, router_id),
        )

    def pending_routing_save(self, tg_id: int, router_id: str,
                             added: list[str], removed: list[str]) -> None:
        added_j = json.dumps(added, ensure_ascii=False)
        removed_j = json.dumps(removed, ensure_ascii=False)
        self.ex(
            """INSERT INTO pending_routing(tg_id, router_id, added_json, removed_json, updated_at)
               VALUES (?,?,?,?, datetime('now'))
               ON CONFLICT(tg_id, router_id) DO UPDATE SET
                 added_json=excluded.added_json,
                 removed_json=excluded.removed_json,
                 updated_at=excluded.updated_at""",
            (tg_id, router_id, added_j, removed_j),
        )

    def pending_routing_clear(self, tg_id: int, router_id: str) -> None:
        self.ex(
            "DELETE FROM pending_routing WHERE tg_id=? AND router_id=?",
            (tg_id, router_id),
        )

    # =========================================================================
    # Stage 3 / Клиент пкт 2: client_logs.
    # =========================================================================
    def add_client_log(self, tg_id: int, username: str | None, router_id: str,
                       log_path: str, preview: str) -> int:
        cur = self.ex(
            """INSERT INTO client_logs(tg_id, username, router_id, log_path, preview)
               VALUES (?,?,?,?,?)""",
            (tg_id, username, router_id, log_path, preview),
        )
        return int(cur.lastrowid)

    def get_client_log(self, log_id: int) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM client_logs WHERE id=?", (log_id,))

    def mark_client_log_read(self, log_id: int) -> None:
        self.ex("UPDATE client_logs SET read_by_admin=1 WHERE id=?", (log_id,))

    def client_logs_list(self, offset: int = 0, limit: int = 20,
                         unread_only: bool = False) -> list[sqlite3.Row]:
        if unread_only:
            return self.q(
                """SELECT * FROM client_logs WHERE read_by_admin=0
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            )
        return self.q(
            "SELECT * FROM client_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def client_logs_unread_count(self) -> int:
        row = self.q1(
            "SELECT COUNT(*) AS c FROM client_logs WHERE read_by_admin=0"
        )
        return int(row["c"]) if row else 0

    def client_logs_retention_cleanup(self, days: int = 30) -> list[str]:
        """Удаляет записи старше N дней, возвращает список log_path'ов для удаления с диска."""
        rows = self.q(
            "SELECT log_path FROM client_logs WHERE created_at < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        paths = [r["log_path"] for r in rows if r["log_path"]]
        self.ex(
            "DELETE FROM client_logs WHERE created_at < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        return paths

    # =========================================================================
    # beta07 / F5: speedtests
    # =========================================================================

    def add_speedtest(
        self,
        router_id: str,
        triggered_by: str | None,
        intl_mbps: float | None,
        ru_mbps: float | None,
        intl_ping_ms: float | None,
        ru_ping_ms: float | None,
        intl_http: int | None,
        ru_http: int | None,
        verdict: str,
    ) -> int:
        """Сохраняет один замер. Возвращает rowid."""
        cur = self._conn.execute(
            """INSERT INTO speedtests(router_id, ts, triggered_by,
                                       intl_mbps, ru_mbps,
                                       intl_ping_ms, ru_ping_ms,
                                       intl_http, ru_http, verdict)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                router_id,
                int(time.time()),
                triggered_by,
                intl_mbps,
                ru_mbps,
                intl_ping_ms,
                ru_ping_ms,
                intl_http,
                ru_http,
                verdict,
            ),
        )
        return int(cur.lastrowid or 0)

    def get_last_speedtest(self, router_id: str) -> Optional[sqlite3.Row]:
        """Последний (по времени) замер для конкретного роутера. None если нет.
        id DESC как tie-breaker — два теста, попавшие в одну секунду, отдадут
        более поздний по id (по сути по порядку INSERT)."""
        return self.q1(
            """SELECT * FROM speedtests
               WHERE router_id=? ORDER BY ts DESC, id DESC LIMIT 1""",
            (router_id,),
        )

    def get_speedtest_history(
        self, router_id: str, days: int = 30, limit: int = 100
    ) -> list[sqlite3.Row]:
        """История за последние N дней (макс limit записей, сначала свежие)."""
        cutoff = int(time.time()) - int(days) * 86400
        return self.q(
            """SELECT * FROM speedtests
               WHERE router_id=? AND ts >= ?
               ORDER BY ts DESC, id DESC LIMIT ?""",
            (router_id, cutoff, limit),
        )

    def count_speedtests_today(
        self, router_id: str, tg_id: int | None = None
    ) -> int:
        """Сколько спидтестов запущено сегодня (UTC) на этом роутере.
        Если передан `tg_id` — считаем только запуски от этого пользователя
        (по строке `triggered_by`, формат "*:<tg_id>").
        Если `tg_id is None` — считаем все запуски на роутере.
        """
        # Начало сегодняшних суток в UTC.
        from datetime import datetime as _dt
        now = _dt.utcnow()
        midnight = int(_dt(now.year, now.month, now.day).timestamp())
        if tg_id is None:
            row = self.q1(
                """SELECT COUNT(*) AS c FROM speedtests
                   WHERE router_id=? AND ts >= ?""",
                (router_id, midnight),
            )
        else:
            # triggered_by заканчивается на ":<tg_id>" — ищем по LIKE.
            pattern = f"%:{int(tg_id)}"
            row = self.q1(
                """SELECT COUNT(*) AS c FROM speedtests
                   WHERE router_id=? AND ts >= ? AND triggered_by LIKE ?""",
                (router_id, midnight, pattern),
            )
        return int(row["c"]) if row else 0

    def prune_speedtests(self, days: int = 30) -> int:
        """Удаляет замеры старше N дней. Возвращает количество удалённых строк."""
        cutoff = int(time.time()) - int(days) * 86400
        cur = self._conn.execute(
            "DELETE FROM speedtests WHERE ts < ?",
            (cutoff,),
        )
        return int(cur.rowcount or 0)

    # Stage 3 / доп: wifi_history (без паролей).
    def add_wifi_history(self, router_id: str, ssid_before: str | None,
                        ssid_after: str | None, tg_id: int | None) -> None:
        self.ex(
            """INSERT INTO wifi_history(router_id, ssid_before, ssid_after, tg_id)
               VALUES (?,?,?,?)""",
            (router_id, ssid_before, ssid_after, tg_id),
        )

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

    # =========================================================================
    # beta07 / F6: allowed_users (whitelist).
    # Бот закрытый: пускаем только cfg.admins и тех, кто в этой таблице.
    # Все методы работают через автокоммит (isolation_level=None).
    # =========================================================================

    def is_allowed(self, tg_id: int) -> bool:
        """True если tg_id в whitelist. Админов из cfg.admins проверяет вызывающий
        код — здесь только сама таблица."""
        if not tg_id:
            return False
        return self.q1(
            "SELECT 1 FROM allowed_users WHERE tg_id=?", (tg_id,)
        ) is not None

    def allow_user(
        self,
        tg_id: int,
        username: str | None = None,
        added_by: int | None = None,
        note: str | None = None,
    ) -> bool:
        """UPSERT в whitelist. Возвращает True, если пользователь был добавлен
        впервые (новый), False — если запись уже существовала и обновлена."""
        existing = self.q1(
            "SELECT 1 FROM allowed_users WHERE tg_id=?", (tg_id,)
        )
        now = int(time.time())
        if existing:
            # Обновляем username/note (но не added_by/added_at, они исторические).
            self.ex(
                """UPDATE allowed_users
                   SET username = COALESCE(?, username),
                       note     = COALESCE(?, note)
                   WHERE tg_id=?""",
                (username, note, tg_id),
            )
            return False
        self.ex(
            """INSERT INTO allowed_users(tg_id, username, added_by, added_at, note)
               VALUES (?,?,?,?,?)""",
            (tg_id, username, added_by, now, note),
        )
        return True

    def deny_user(self, tg_id: int) -> bool:
        """Удалить из whitelist. True если запись была."""
        cur = self.ex("DELETE FROM allowed_users WHERE tg_id=?", (tg_id,))
        return (cur.rowcount or 0) > 0

    def list_allowed(self) -> list[sqlite3.Row]:
        """Список всех whitelisted (свежие сначала)."""
        return self.q(
            "SELECT * FROM allowed_users ORDER BY added_at DESC, tg_id ASC"
        )

    def count_allowed(self) -> int:
        row = self.q1("SELECT COUNT(*) AS c FROM allowed_users")
        return int(row["c"]) if row else 0

    def find_user_by_username(self, username: str) -> Optional[int]:
        """Резолв @username → tg_id по таблице clients (тот, кто хоть раз писал).
        Регистронезависимо. None если не нашли. Сначала ищем в clients
        (живые контакты бота), затем в allowed_users (мог быть добавлен по
        username руками без обращения в бота)."""
        if not username:
            return None
        u = username.strip().lstrip("@")
        if not u:
            return None
        row = self.q1(
            "SELECT tg_id FROM clients WHERE LOWER(username)=LOWER(?) LIMIT 1",
            (u,),
        )
        if row:
            return int(row["tg_id"])
        row = self.q1(
            "SELECT tg_id FROM allowed_users WHERE LOWER(username)=LOWER(?) LIMIT 1",
            (u,),
        )
        if row:
            return int(row["tg_id"])
        return None

    def get_allowed(self, tg_id: int) -> Optional[sqlite3.Row]:
        return self.q1("SELECT * FROM allowed_users WHERE tg_id=?", (tg_id,))

    def migrate_allowed_users_from_owners(self) -> int:
        """beta07: одноразовая миграция — все клиенты с привязанным роутером
        автоматически попадают в whitelist. Идемпотентна по `meta_flag`-ключу
        в settings (запускается один раз; повторные вызовы возвращают 0).
        Возвращает количество фактически добавленных строк."""
        FLAG_KEY = "beta07_whitelist_migrated"
        if self.get_setting(FLAG_KEY, False):
            return 0
        rows = self.q(
            """SELECT DISTINCT c.tg_id, c.username
               FROM clients c
               JOIN bindings b ON b.tg_id = c.tg_id
               WHERE c.tg_id IS NOT NULL"""
        )
        added = 0
        now = int(time.time())
        for r in rows:
            tg_id = int(r["tg_id"])
            username = r["username"]
            cur = self.ex(
                """INSERT OR IGNORE INTO allowed_users
                   (tg_id, username, added_by, added_at, note)
                   VALUES (?,?,?,?,?)""",
                (tg_id, username, None, now, "auto-migrated from beta06"),
            )
            if cur.rowcount:
                added += 1
        self.set_setting(FLAG_KEY, True)
        return added

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
