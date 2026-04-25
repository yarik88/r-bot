"""
r-bot — Telegram-бот управления OpenWrt роутерами через FRP.

Запуск:
    python3 r_bot.py              # обычный
    python3 r_bot.py --init-db    # инициализация + seed admin'ов из bot.yaml

Конфиг: /etc/r/bot.yaml (см. config/bot.yaml.example)
БД: /var/lib/r-bot/bot.db
Лог: /var/log/r-bot.log

Зависимости: python-telegram-bot[job-queue] >=21, paramiko, pyyaml.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import gzip
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import yaml
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile,
    Update,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# Локальные модули
sys.path.insert(0, str(Path(__file__).parent))
from db import DB                                        # noqa: E402
from router import (                                     # noqa: E402
    Router,
    all_slots_from_config,
    cfg_edit_label,
    discover,
    do_capture_client_log,
    do_get_routing,
    do_get_vless,
    do_get_wifi,
    do_global_check,
    do_info,
    do_logread,
    do_ping,
    do_podkop_logs,
    do_podkop_restart,
    do_reboot,
    do_router_selftest,
    do_set_routing,
    do_set_vless,
    do_set_wifi,
    mask_vless_for_audit,
    parse_vless,
    poll_all,
    poll_router,
    validate_custom_vless,
    validate_domain,
)


# =============================================================================
# Константы / дефолты
# =============================================================================

VERSION = "1.0"
DEFAULT_CFG_PATH = "/etc/r/bot.yaml"

DEFAULT_CFG: dict[str, Any] = {
    "digest": {"enabled": True, "time": "09:00", "timezone": "Europe/Moscow"},
    "poll": {"interval_minutes": 15, "ssh_timeout_sec": 10, "parallel_workers": 10},
    "backup": {
        "daily_cron": "03:00",
        "weekly_telegram": True,
        "weekly_time": "10:00",
        "weekly_day": "Sun",
        "keep_days": 14,
    },
    "auto_update": {
        "enabled": False,
        "time": "04:00",
        "branch": "main",
        "repo_dir": "/opt/r-bot-src",
    },
    "paths": {
        "r_config": "/etc/r/config.yaml",
        "db": "/var/lib/r-bot/bot.db",
        "log": "/var/log/r-bot.log",
        "runs": "/var/lib/r-bot/runs",
        "backups": "/var/backups/r-bot",
        # Stage 3 / Клиент пкт 2: директория для клиентских логов.
        "client_logs": "/var/lib/r-bot/client_logs",
    },
    "rate_limits": {
        "reboot_per_day": 5,
        "podkop_restart_per_day": 10,
        "vless_change_per_day": 20,
        "global_check_per_day": 50,
        # Stage 2 / клиент пкт 7:
        "wifi_change_per_day": 5,
        # Stage 3 / клиент пкт 8 и 2:
        "routing_add_per_day": 20,
        "routing_del_per_day": 20,
        "send_log_per_day":    5,
    },
    # Stage 3 / A7: retention audit (дней).
    "audit_retention_days":       90,
    # Stage 3 / клиент пкт 8: потолок списка доменов.
    "routing_max_domains":        200,
    # Stage 3 / клиент пкт 2: retention клиентских логов (дней).
    "client_logs_retention_days": 30,
    # Stage 3 / A6: куда слать push. Пусто = всем из admins.
    "admin_chat_ids":             [],
    "clients": {},
}

# HTML-escape для подстановок в сообщения
def esc(x: Any) -> str:
    return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# =============================================================================
# Конфиг
# =============================================================================

def deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_cfg(path: str = DEFAULT_CFG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        user = yaml.safe_load(f) or {}
    cfg = deep_merge(DEFAULT_CFG, user)
    if not cfg.get("token") or cfg["token"].startswith("PASTE"):
        raise SystemExit(f"В {path} не прописан token")
    if not cfg.get("admins"):
        raise SystemExit(f"В {path} не прописаны admins (твой TG user id)")
    return cfg


def load_r_config(cfg: dict) -> dict:
    path = cfg["paths"]["r_config"]
    with open(path, "r", encoding="utf-8") as f:
        rc = yaml.safe_load(f) or {}
    ssh = rc.get("ssh") or {}
    if not ssh.get("password"):
        raise SystemExit(f"В {path} не указан ssh.password")
    rc.setdefault("overrides", {})
    # Stage 1 / A4: max_routers=999. Расширили дефолтные диапазоны портов
    # с 99 до 999. Существующие deployments с портами 10001-10099/11001-11099
    # продолжают работать без изменений (id07 → 10007/11007).
    rc.setdefault("web_port_range", [10001, 10999])
    rc.setdefault("ssh_port_range", [11001, 11999])
    return rc


# =============================================================================
# Логгер
# =============================================================================

def setup_logging(path: str) -> logging.Logger:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # заглушаем болтливый telegram
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.INFO)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    return logging.getLogger("r-bot")


# =============================================================================
# Вспомогательные
# =============================================================================

def kb(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(rows)


def btn(label: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(label, callback_data=data)


def status_icon(online: bool, podkop: str | None, lifecycle: str | None = None) -> str:
    # Stage 2 / A1: lifecycle перекрывает обычный статус.
    #   transit       — 🟣 (едет к клиенту, не опрашивается)
    #   maintenance   — 🛠 (техработы, не опрашивается)
    if lifecycle == "transit":
        return "🟣"
    if lifecycle == "maintenance":
        return "🛠"
    if not online:
        return "🔴"
    if podkop == "RUN":
        return "🟢"
    # Stage 1: новый статус BYPASS — sing-box работает, но трафик идёт мимо
    # VLESS (egress IP == local IP). Жёлтый предупреждающий.
    if podkop == "BYPASS":
        return "🟡"
    if podkop == "STOP":
        return "🟠"   # ярко-оранжевый: подкоп упал на онлайн-роутере
    return "⚪"


def _row_lifecycle(st) -> str | None:
    """Безопасно достаёт lifecycle_status из sqlite3.Row — на старых записях
    колонки может не быть в Row, либо значение NULL."""
    if st is None:
        return None
    try:
        v = st["lifecycle_status"]
    except (IndexError, KeyError):
        return None
    return v or None


def _country_flag(iso: str) -> str:
    """ISO 3166 alpha-2 ('DE') → 🇩🇪 (regional indicator pair). Возвращает
    пустую строку, если код некорректный или пустой. Не делает доп.
    запросов — чисто строковое преобразование."""
    if not iso or len(iso) != 2 or not iso.isalpha():
        return ""
    iso = iso.upper()
    base = 0x1F1E6  # regional indicator A
    return chr(base + (ord(iso[0]) - ord("A"))) + chr(base + (ord(iso[1]) - ord("A")))


def _short_vless(url: str) -> str:
    """Stage 1 / Пункт 4: для клиента не показываем полный vless:// URL.
    Возвращает host (без порта/UUID), пригодный к подстановке во флаг+домен.
    Если парсинг не удался — пустая строка."""
    if not url:
        return ""
    try:
        # parse_vless импортируется ниже; используем локальный мини-парсер
        # чтобы избежать циклического импорта при загрузке модуля.
        from urllib.parse import urlparse
        p = urlparse(url.replace("vless://", "http://", 1))
        return p.hostname or ""
    except Exception:
        return ""


def is_admin(ctx: ContextTypes.DEFAULT_TYPE, tg_id: int) -> bool:
    cfg: dict = ctx.application.bot_data["cfg"]
    if tg_id in cfg.get("admins", []):
        return True
    db: DB = ctx.application.bot_data["db"]
    row = db.get_client(tg_id)
    return bool(row and row["role"] == "admin")


def user_role(ctx: ContextTypes.DEFAULT_TYPE, tg_id: int) -> str:
    cfg: dict = ctx.application.bot_data["cfg"]
    if tg_id in cfg.get("admins", []):
        return "admin"
    db: DB = ctx.application.bot_data["db"]
    row = db.get_client(tg_id)
    if not row:
        return "unknown"
    return row["role"]


def client_owns_router(ctx: ContextTypes.DEFAULT_TYPE, tg_id: int, rid: str) -> bool:
    if is_admin(ctx, tg_id):
        return True
    db: DB = ctx.application.bot_data["db"]
    return rid in db.client_routers(tg_id)


async def reply_or_edit(update: Update, text: str, keyboard: InlineKeyboardMarkup | None = None, **kw):
    kw.setdefault("parse_mode", ParseMode.HTML)
    kw.setdefault("disable_web_page_preview", True)
    if update.callback_query:
        await update.callback_query.answer()
        try:
            await update.callback_query.edit_message_text(text, reply_markup=keyboard, **kw)
            return
        except Exception:
            pass
    if update.message:
        await update.message.reply_text(text, reply_markup=keyboard, **kw)


# =============================================================================
# Клавиатуры
# =============================================================================

def kb_main_admin(db: DB) -> InlineKeyboardMarkup:
    pending = len(db.pending_requests())
    req_label = f"📮 Заявки ({pending})" if pending else "📮 Заявки"
    # Stage 3 / A7+S3-4: показать бейдж непрочитанных клиентских логов.
    try:
        unread_logs = db.client_logs_unread_count()
    except Exception:
        unread_logs = 0
    clog_label = f"📥 Логи от клиентов ({unread_logs})" if unread_logs else "📥 Логи от клиентов"
    return kb(
        [
            [btn("📊 Все роутеры", "list:all:0"), btn("⚠️ Проблемные", "list:bad:0")],
            [btn("👥 Клиенты", "cli:list"), btn(req_label, "req:list")],
            [btn("🎟 Коды", "inv:list"), btn("🔗 VLESS-пул", "pool:list")],
            [btn("🧪 Глобальный тест", "gt:run"), btn(clog_label, "clog:list:0")],
            [btn("🔔 Mass", "mass:menu"), btn("⚙️ Настройки", "cfg:menu")],
            [btn("🔄 Обновить данные", "poll:now")],
        ]
    )


def kb_main_client(db: DB, tg_id: int) -> InlineKeyboardMarkup:
    # Stage 2 / A1: роутеры в transit клиент не видит — они ещё не активированы
    # и физически могут ехать к нему. Maintenance показываем с плашкой 🛠.
    rids = db.client_routers(tg_id)
    rows = []
    for rid in rids:
        st = db.get_state(rid)
        lifecycle = _row_lifecycle(st)
        if lifecycle == "transit":
            continue
        icon = status_icon(
            bool(st and st["online"]),
            st["podkop_status"] if st else None,
            lifecycle,
        )
        label = (st["label"] if st and st["label"] else rid)
        rows.append([btn(f"{icon} {rid} — {label}", f"r:{rid}")])
    rows.append([btn("🔄 Обновить", "poll:now")])
    return kb(rows)


def kb_welcome_guest() -> InlineKeyboardMarkup:
    return kb(
        [
            [btn("🎟 У меня есть код", "guest:code")],
            [btn("📮 Подать заявку", "guest:request")],
        ]
    )


def kb_router_menu(rid: str, role: str, st=None) -> InlineKeyboardMarkup:
    # Stage 1 / Пункты 5, 6: переименованы кнопки.
    #   "🔧 Restart podkop"  → "🔄 Перезагрузить службу"
    #   "🔁 Reboot"          → "♻️ Перезагрузить Роутер (рекомендуется)"
    # Stage 2 / Пункт 7: добавлена кнопка "📶 WiFi" (всем).
    # Stage 2 / A1, A2, A9: админские кнопки lifecycle / custom VLESS / владельцы.
    is_admin_user = (role == "admin")
    lifecycle = _row_lifecycle(st)
    custom_vless = ""
    if st is not None:
        try:
            custom_vless = st["custom_vless_url"] or ""
        except (IndexError, KeyError):
            custom_vless = ""

    # Stage 2 / A1: для роутеров в техработах клиент не должен видеть кнопок
    # действий — только статус и сообщение. См. _show_router (обработка
    # maintenance возвращает плашку без меню).
    rows = [
        [btn("🔄 Статус", f"r:{rid}"), btn("▶️ Проверить", f"act:{rid}:check")],
        [btn("🔄 Перезагрузить службу", f"act:{rid}:pres")],
        [btn("♻️ Перезагрузить Роутер (рекомендуется)", f"act:{rid}:boot")],
        [btn("🔗 Сменить VLESS", f"vless:pick:{rid}:0")],
        [btn("📶 WiFi", f"wifi:menu:{rid}")],
        # Stage 3 / Клиент пкт 8: маршрутизация всем привязанным.
        [btn("📋 Маршрутизация", f"rt:menu:{rid}")],
    ]
    if is_admin_user:
        rows.append([btn("📜 Logs", f"act:{rid}:logs"), btn("📜 Podkop logs", f"act:{rid}:plogs")])
        rows.append([btn("ℹ️ Info", f"act:{rid}:info"), btn("📜 Аудит роутера", f"aud:r:{rid}:0")])
        # A2: custom VLESS / возврат в пул — взаимоисключающие.
        if custom_vless:
            rows.append([btn("🔁 Вернуть в пул", f"vless:pool:{rid}")])
        else:
            rows.append([btn("🔧 Custom VLESS", f"vless:custom:{rid}")])
        # A1: lifecycle-кнопки. Состояние-зависимое.
        if lifecycle == "transit":
            rows.append([btn("✅ Активировать", f"act:{rid}:activate")])
        elif lifecycle == "maintenance":
            rows.append([btn("▶ Снять техработы", f"act:{rid}:maintenance_off")])
        else:
            rows.append([
                btn("🛠 Техработы", f"act:{rid}:maintenance"),
                btn("🚚 В пути", f"act:{rid}:in_transit"),
            ])
        # A9: владельцы.
        rows.append([
            btn("👥 Владельцы", f"own:list:{rid}"),
        ])
        rows.append(
            [
                btn("✏️ Переименовать", f"label:ren:{rid}"),
                btn("🗑 Удалить из мониторинга", f"label:del:{rid}"),
            ]
        )
    rows.append([btn("← Главная", "menu:main")])
    return kb(rows)


def kb_confirm(yes_data: str, no_data: str = "menu:main", yes_label: str = "✅ Да", no_label: str = "❌ Отмена") -> InlineKeyboardMarkup:
    return kb([[btn(yes_label, yes_data), btn(no_label, no_data)]])


# =============================================================================
# Сборка состояния роутеров (из БД + текущего discovery)
# =============================================================================

def current_routers(ctx: ContextTypes.DEFAULT_TYPE) -> list[Router]:
    """Текущий срез: роутеры из discovery + labels из r_config."""
    rcfg: dict = ctx.application.bot_data["r_config"]
    return discover(rcfg)


def all_router_ids(ctx: ContextTypes.DEFAULT_TYPE) -> list[str]:
    """Все idNN, которые когда-либо видели (из state) + текущие онлайн."""
    rcfg: dict = ctx.application.bot_data["r_config"]
    db: DB = ctx.application.bot_data["db"]
    ids = set(all_slots_from_config(rcfg))
    for r in discover(rcfg):
        ids.add(r.id)
    for st in db.all_states():
        ids.add(st["router_id"])
    return sorted(ids)


def router_by_id(ctx: ContextTypes.DEFAULT_TYPE, rid: str) -> Optional[Router]:
    """Попытаться получить «живой» Router (для SSH). Если оффлайн — None."""
    for r in current_routers(ctx):
        if r.id == rid:
            return r
    return None


# =============================================================================
# /start
# =============================================================================

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u:
        return
    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    # Автозавод admin'ов из cfg.admins при первом /start
    if u.id in cfg.get("admins", []):
        db.set_admin(u.id, u.username)
    # Stage 3 / A6: если клиент ранее не был в БД — уведомить админа о первом /start.
    is_new_client = (
        db.get_client(u.id) is None
        and u.id not in cfg.get("admins", [])
    )
    db.upsert_client(u.id, u.username, u.first_name, role=db.get_client(u.id)["role"] if db.get_client(u.id) else "client")
    db.touch_seen(u.id)
    if is_new_client:
        try:
            await _push_admins(
                ctx,
                f"👋 <b>Новый клиент /start</b>\n"
                f"@{esc(u.username or '—')} "
                f"(<code>{u.id}</code>, {esc(u.first_name or '')})",
                kb([[btn("👥 Клиенты", "cli:list")]]),
            )
        except Exception:
            pass

    role = user_role(ctx, u.id)
    if role == "admin":
        text = _admin_summary(ctx)
        await reply_or_edit(update, text, kb_main_admin(db))
    elif role == "client":
        rids = db.client_routers(u.id)
        if not rids:
            await reply_or_edit(
                update,
                "Привет! К твоему аккаунту пока не привязан ни один роутер.\n\n"
                "Введи одноразовый код от администратора или подай заявку.",
                kb_welcome_guest(),
            )
        else:
            text = f"Твои роутеры ({len(rids)}):"
            await reply_or_edit(update, text, kb_main_client(db, u.id))
    else:
        # unknown — первый /start не-админа
        await reply_or_edit(
            update,
            "Привет! Этот бот управляет роутерами. Доступ только по приглашению.\n\n"
            "Если у тебя есть код — нажми «У меня есть код».\n"
            "Или подай заявку администратору.",
            kb_welcome_guest(),
        )


def _admin_summary(ctx: ContextTypes.DEFAULT_TYPE) -> str:
    db: DB = ctx.application.bot_data["db"]
    states = db.all_states()
    total = len(states)
    online = sum(1 for s in states if s["online"])
    offline = total - online
    stopped = sum(1 for s in states if s["online"] and s["podkop_status"] == "STOP")
    last = "никогда"
    last_polls = [s["last_poll_at"] for s in states if s["last_poll_at"]]
    if last_polls:
        last = max(last_polls)
    pending = len(db.pending_requests())
    msg = (
        f"<b>r-bot v{VERSION}</b> — админ-панель\n\n"
        f"Всего роутеров: <b>{total}</b>\n"
        f"🟢 online: {online}  ·  🔴 offline: {offline}  ·  🟡 podkop STOP: {stopped}\n"
        f"Последний опрос: {last}\n"
    )
    if pending:
        msg += f"\n📮 Заявок на одобрение: <b>{pending}</b>"
    return msg


# =============================================================================
# Список роутеров (admin)
# =============================================================================

# Stage 2 / A3: 3 кнопки в ряд → 10 рядов на страницу = 30 роутеров.
# Влезает в один экран мобильника, не нужно листать в типичном случае
# (50 устройств = 2 страницы).
PAGE_SIZE = 30
LIST_COLS = 3


async def cb_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, mode, page_s = q.data.split(":")
    page = int(page_s)
    await _show_list(update, ctx, mode, page)


def _owner_short_map(db: DB, rids: list[str]) -> dict[str, str]:
    """Собирает {rid → 'owner4'} для подписи на компактной кнопке.
    Берётся первый по сортировке по tg_id (стабильно). Если владельцев нет —
    пустая строка."""
    if not rids:
        return {}
    placeholders = ",".join("?" * len(rids))
    rows = db.q(
        f"""SELECT b.router_id, c.username, c.first_name
            FROM bindings b
            LEFT JOIN clients c ON c.tg_id = b.tg_id
            WHERE b.router_id IN ({placeholders})
            ORDER BY b.router_id, b.tg_id""",
        tuple(rids),
    )
    out: dict[str, str] = {}
    for r in rows:
        rid = r["router_id"]
        if rid in out:
            continue   # уже взяли первого
        name = (r["username"] or r["first_name"] or "").strip()
        if name:
            out[rid] = name[:4]
    return out


async def _show_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE, mode: str, page: int):
    db: DB = ctx.application.bot_data["db"]
    all_ids = all_router_ids(ctx)
    states = {s["router_id"]: s for s in db.all_states()}

    def lifecycle_of(rid: str) -> str | None:
        s = states.get(rid)
        if not s:
            return None
        try:
            return s["lifecycle_status"] or None
        except (IndexError, KeyError):
            return None

    def effective_status(rid: str) -> str:
        """Возвращает один из: 'online'/'offline'/'transit'/'maintenance'.
        Lifecycle перекрывает poll-статус."""
        ls = lifecycle_of(rid)
        if ls in ("transit", "maintenance"):
            return ls
        s = states.get(rid)
        return "online" if (s and s["online"]) else "offline"

    # Stage 2 / A1: пять режимов фильтра — online/offline/transit/maintenance/all.
    # «bad» оставляем для обратной совместимости (старые callback ссылки).
    def matches(rid: str) -> bool:
        es = effective_status(rid)
        if mode == "all":
            return True
        if mode == "online":
            return es == "online"
        if mode == "offline":
            return es == "offline"
        if mode == "transit":
            return es == "transit"
        if mode == "maint":
            return es == "maintenance"
        if mode == "bad":   # legacy
            s = states.get(rid)
            online = es == "online"
            podkop = s["podkop_status"] if s else None
            return (not online) or (podkop == "STOP")
        return True

    # Подсчёт по всем категориям сразу — для счётчиков на чипах.
    counts = {"online": 0, "offline": 0, "transit": 0, "maintenance": 0}
    for rid in all_ids:
        es = effective_status(rid)
        if es in counts:
            counts[es] += 1

    filtered = [r for r in all_ids if matches(r)]
    total = len(filtered)
    start = page * PAGE_SIZE
    chunk = filtered[start : start + PAGE_SIZE]

    rcfg: dict = ctx.application.bot_data["r_config"]
    overrides = rcfg.get("overrides") or {}
    owner_map = _owner_short_map(db, chunk)

    rows: list = []
    cur_row: list = []
    for rid in chunk:
        s = states.get(rid)
        online = bool(s and s["online"])
        podkop = s["podkop_status"] if s else None
        ls = lifecycle_of(rid)
        icon = status_icon(online, podkop, ls)
        owner4 = owner_map.get(rid, "")
        # Компактная подпись: «🟢 id07 yari». Override label не вмещаем —
        # увидит на экране роутера. owner4 важнее для парк-менеджмента.
        short = f"{icon} {rid}" + (f" {owner4}" if owner4 else "")
        cur_row.append(btn(short, f"r:{rid}"))
        if len(cur_row) >= LIST_COLS:
            rows.append(cur_row)
            cur_row = []
    if cur_row:
        rows.append(cur_row)

    nav = []
    if page > 0:
        nav.append(btn("← назад", f"list:{mode}:{page-1}"))
    if start + PAGE_SIZE < total:
        nav.append(btn("вперёд →", f"list:{mode}:{page+1}"))
    if nav:
        rows.append(nav)

    # Stage 2 / A1: фильтры lifecycle с числовыми счётчиками. Активный — точкой.
    def chip(label: str, m: str, n: int | None = None) -> object:
        cnt = "" if n is None else f" ({n})"
        suf = " •" if mode == m else ""
        return btn(f"{label}{cnt}{suf}", f"list:{m}:0")

    rows.append([
        chip("🟢", "online", counts["online"]),
        chip("🔴", "offline", counts["offline"]),
        chip("🟣", "transit", counts["transit"]),
        chip("🛠", "maint", counts["maintenance"]),
    ])
    rows.append([
        chip("📋 все", "all", len(all_ids)),
        # Заглушка для будущего поиска (оставляем чтобы кнопка появилась
        # сразу — реализация в Stage 3 / отдельной правке).
        btn("🔍 Поиск (скоро)", "list:search_stub"),
    ])
    rows.append([btn("← Главная", "menu:main")])

    title_map = {
        "all": "все", "online": "🟢 online", "offline": "🔴 offline",
        "transit": "🟣 transit", "maint": "🛠 maintenance", "bad": "проблемные",
    }
    text = (
        f"<b>Роутеры — {title_map.get(mode, mode)}</b>\n"
        f"Показано {len(chunk)} из {total}\n"
        f"Страница {page+1}/{max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)}"
    )
    await reply_or_edit(update, text, kb(rows))


async def cb_list_search_stub(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Заглушка для кнопки 'Поиск (скоро)' — отвечаем alert'ом, не уходим
    с экрана. Stage 3 заменит на реальный поиск по id/owner."""
    q = update.callback_query
    if q:
        await q.answer("Поиск появится в Stage 3", show_alert=False)


# =============================================================================
# Меню одного роутера
# =============================================================================

async def cb_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, rid = q.data.split(":")
    await _show_router(update, ctx, rid)


async def _show_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE, rid: str):
    u = update.effective_user
    if not u:
        return
    if not client_owns_router(ctx, u.id, rid):
        await reply_or_edit(update, "Этого роутера нет в твоих привязках.", kb([[btn("← Главная", "menu:main")]]))
        return

    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    st = db.get_state(rid)
    overrides = rcfg.get("overrides") or {}
    label = overrides.get(rid) or (st["label"] if st and st["label"] else "(без имени)")
    role = user_role(ctx, u.id)
    is_admin_user = (role == "admin")

    # Stage 2 / A1: lifecycle. Клиент с transit-роутером сюда не должен попадать
    # (фильтр в client_routers_visible), но если попал по прямой ссылке —
    # отказываем. На maintenance клиенту показываем серую плашку без кнопок.
    lifecycle = _row_lifecycle(st)
    if lifecycle == "transit" and not is_admin_user:
        await reply_or_edit(
            update,
            "Этот роутер пока не активирован администратором.",
            kb([[btn("← Главная", "menu:main")]]),
        )
        return
    if lifecycle == "maintenance" and not is_admin_user:
        await reply_or_edit(
            update,
            f"<b>{rid}</b> — {esc(label)}\n\n🛠 Техработы, попробуйте позже.",
            kb([[btn("🔄 Обновить статус", f"r:{rid}"), btn("← Главная", "menu:main")]]),
        )
        return

    if st:
        is_admin = is_admin_user
        icon = status_icon(bool(st["online"]), st["podkop_status"], lifecycle)
        if lifecycle == "transit":
            status = "🟣 transit (едет к клиенту)"
        elif lifecycle == "maintenance":
            status = "🛠 maintenance (техработы)"
        else:
            status = "online" if st["online"] else "offline"
        podkop = st["podkop_status"] or "—"
        up = st["uptime"] or "—"
        wan = st["wan_ip"] or ""
        last = st["last_poll_at"] or "—"

        # Stage 1 / Пункты 1, 3, 4: достаём новые поля. На старых записях
        # колонки уже добавлены миграцией, но значения могут быть NULL.
        # Безопасное чтение: KeyError/IndexError → пустая строка.
        def _g(col: str) -> str:
            try:
                v = st[col]
            except (IndexError, KeyError):
                return ""
            return v if v else ""

        local_ip = _g("local_ip")
        egress_ip = _g("egress_ip")
        egress_country_iso = _g("egress_country_iso")
        egress_city = _g("egress_city")
        egress_asn_org = _g("egress_asn_org")
        active_vless = _g("active_vless")
        hw_model = _g("hw_model")
        openwrt_version = _g("openwrt_version")
        podkop_version = _g("podkop_version")
        singbox_version = _g("singbox_version")
        flag = _country_flag(egress_country_iso)

        lines = [
            f"<b>{rid}</b> — {esc(label)}",
            f"{icon} {status}",
            f"podkop: <b>{esc(podkop)}</b>",
            f"uptime: {esc(up)}",
        ]
        # Пункт 3: показываем «локальный IP» (yandex), если есть, иначе старый
        # WAN от OpenWrt. Они могут отличаться на 4G CGNAT.
        if local_ip:
            lines.append(f"локальный IP: <code>{esc(local_ip)}</code>")
        elif wan:
            lines.append(f"WAN: <code>{esc(wan)}</code>")
        # Пункт 1: выходной IP с флагом, городом, ASN.
        if egress_ip:
            extras = [x for x in (egress_city, egress_asn_org) if x]
            extra = (" · " + esc(" · ".join(extras))) if extras else ""
            flag_part = (flag + " ") if flag else ""
            lines.append(f"выход: {flag_part}<code>{esc(egress_ip)}</code>{extra}")
        # Пункт 4: VLESS — клиенту только host, админу полный URL.
        if active_vless:
            if is_admin:
                lines.append(f"VLESS: <code>{esc(active_vless)}</code>")
            else:
                short = _short_vless(active_vless)
                if short:
                    lines.append(f"VLESS: <code>{esc(short)}</code>")
        # Stage 2 / A2: для админа — индикатор кастомного VLESS / выхода из пула.
        if is_admin:
            custom_vless = _g("custom_vless_url")
            in_pool_raw = None
            try:
                in_pool_raw = st["in_pool"]
            except (IndexError, KeyError):
                in_pool_raw = None
            if custom_vless:
                lines.append("🔧 <b>custom VLESS</b> (роутер вне пула ротации)")
            elif in_pool_raw == 0:
                lines.append("⚠ роутер вне пула (in_pool=0)")
        # Пункт 1 (часть admin): версионный блок только для админа.
        if is_admin:
            ver_bits = []
            if hw_model:
                ver_bits.append(f"модель: {esc(hw_model)}")
            if openwrt_version:
                ver_bits.append(f"OpenWrt: {esc(openwrt_version)}")
            if podkop_version:
                ver_bits.append(f"podkop: {esc(podkop_version)}")
            if singbox_version:
                ver_bits.append(f"sing-box: {esc(singbox_version)}")
            if ver_bits:
                lines.append("<i>" + "  ·  ".join(ver_bits) + "</i>")
        lines.append(f"последний опрос: {esc(last)}")
        text = "\n".join(lines)
    else:
        text = (
            f"<b>{rid}</b> — {esc(label)}\n"
            "пока не опрошен. Нажми «Обновить статус» или подожди polling."
        )

    await reply_or_edit(update, text, kb_router_menu(rid, role, st))


# =============================================================================
# Действия на роутере: confirm + execute
# =============================================================================

# Stage 1 / Пункты 5, 6: метки приведены к новым русским названиям кнопок.
# Первый элемент кортежа — короткая метка для audit-лога; второй — текст для
# подтверждения "Точно ...?".
ACTION_LABELS = {
    "boot": ("Перезагрузить Роутер", "перезагрузить роутер", "reboot_per_day"),
    "pres": ("Перезагрузить службу", "перезагрузить службу podkop", "podkop_restart_per_day"),
    "check": ("Global check", "запустить global_check", "global_check_per_day"),
    "info": ("Info", "показать info", None),
    "logs": ("Logread", "показать logread", None),
    "plogs": ("Podkop logs", "показать podkop logs", None),
    # Stage 2 / A1: lifecycle (только админ — проверка ниже).
    "maintenance":     ("Техработы",        "перевести роутер в режим техработ", None),
    "maintenance_off": ("Снять техработы",   "снять режим техработ",              None),
    "in_transit":      ("В пути",            "пометить роутер как «в пути»",      None),
    "activate":        ("Активировать",       "активировать роутер",                None),
}

# Stage 2 / A1: множества действий для удобной классификации.
LIFECYCLE_ACTIONS = {"maintenance", "maintenance_off", "in_transit", "activate"}
READONLY_ACTIONS = {"info", "logs", "plogs", "check"}


async def cb_action(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, rid, act = q.data.split(":")
    u = update.effective_user
    if not u:
        return
    if not client_owns_router(ctx, u.id, rid):
        await reply_or_edit(update, "Нет доступа к этому роутеру.", kb([[btn("← Главная", "menu:main")]]))
        return

    label_act, human, rl_key = ACTION_LABELS.get(act, (act, act, None))

    # Stage 2 / A1: lifecycle-действия — только админ.
    if act in LIFECYCLE_ACTIONS:
        if not is_admin(ctx, u.id):
            await reply_or_edit(update, "Только админ.", kb([[btn("← назад", f"r:{rid}")]]))
            return
        # Подтверждение всё равно показываем — это «состояние парка», не
        # хочется случайным тычком увести роутер в transit.
        text = (
            f"<b>{rid}</b>\n\n"
            f"Точно {human}? Изменение lifecycle-статуса будет записано в audit-лог."
        )
        await reply_or_edit(update, text, kb_confirm(f"do:{rid}:{act}", f"r:{rid}"))
        return

    # действия read-only — без подтверждения
    if act in READONLY_ACTIONS:
        await _execute_action(update, ctx, rid, act, first=True)
        return

    # опасные — два нажатия
    text = (
        f"<b>{rid}</b>\n\n"
        f"Точно {human}? Действие будет записано в audit-лог."
    )
    await reply_or_edit(update, text, kb_confirm(f"do:{rid}:{act}", f"r:{rid}"))


async def cb_do(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, rid, act = q.data.split(":")
    await _execute_action(update, ctx, rid, act, first=False)


async def _execute_action(update: Update, ctx: ContextTypes.DEFAULT_TYPE, rid: str, act: str, first: bool):
    u = update.effective_user
    if not u:
        return
    if not client_owns_router(ctx, u.id, rid):
        await reply_or_edit(update, "Нет доступа.", kb([[btn("← Главная", "menu:main")]]))
        return

    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    # Stage 2 / A1: lifecycle-операции — не нужен SSH, не нужен полл, не нужен
    # rate-limit. Просто пишем статус в БД и audit. Делаем это ДО offline-guard,
    # т.к. transit/maintenance чаще всего ставится именно когда роутер не онлайн.
    if act in LIFECYCLE_ACTIONS:
        if not is_admin(ctx, u.id):
            await reply_or_edit(update, "Только админ.", kb([[btn("← назад", f"r:{rid}")]]))
            return
        new_status = {
            "maintenance":     "maintenance",
            "maintenance_off": None,    # снятие — обнуляем lifecycle
            "in_transit":      "transit",
            "activate":        None,    # активация — тоже обнуляем (станет online по поллу)
        }.get(act)
        try:
            db.set_lifecycle(rid, new_status)
            db.audit(u.id, u.username, rid, f"lifecycle:{act}",
                     f"new={new_status!s}", "ok")
            log.info("lifecycle %s %s by %s -> %s", act, rid, u.id, new_status)
        except Exception as e:
            log.exception("lifecycle %s on %s failed", act, rid)
            db.audit(u.id, u.username, rid, f"lifecycle:{act}", None, f"fail: {e}")
            await reply_or_edit(
                update,
                f"❌ Ошибка: <code>{esc(str(e))}</code>",
                kb([[btn("← назад", f"r:{rid}")]]),
            )
            return
        # Перерисовываем карточку роутера — кнопки теперь будут другими
        # (например, после maintenance появится «▶ Снять техработы»).
        await _show_router(update, ctx, rid)
        return

    # rate limit (не для admin)
    role = user_role(ctx, u.id)
    rl_key = ACTION_LABELS.get(act, (None, None, None))[2]
    if role != "admin" and rl_key:
        limit = cfg["rate_limits"].get(rl_key, 0)
        if limit > 0 and not db.rate_check_and_inc(u.id, act, limit):
            await reply_or_edit(
                update,
                f"Лимит на сегодня исчерпан ({limit} операций {rl_key}). Попробуй завтра.",
                kb([[btn("← назад", f"r:{rid}")]]),
            )
            return

    r = router_by_id(ctx, rid)
    if r is None:
        # оффлайн — пишем в audit и возвращаем ошибку
        db.audit(u.id, u.username, rid, act, None, "fail: offline")
        await reply_or_edit(
            update,
            f"<b>{rid}</b> сейчас offline. Дождись возврата в сеть.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    ssh_cfg = rcfg["ssh"]

    # Сначала отрисовать «выполняется...»
    await reply_or_edit(
        update,
        f"<b>{rid}</b> — {esc(ACTION_LABELS.get(act, (act,))[0])}…",
        kb([[btn("← назад", f"r:{rid}")]]),
    )

    # Выполнить в thread executor — paramiko синхронный
    loop = asyncio.get_event_loop()

    try:
        if act == "boot":
            ok, msg = await loop.run_in_executor(None, do_reboot, r, ssh_cfg)
            result = "ok" if ok else f"fail: {msg}"
            log.info("action reboot %s by %s -> %s", rid, u.id, result)
            db.audit(u.id, u.username, rid, "reboot", None, result)
            text = (
                f"<b>{rid}</b> — Reboot\n\n"
                f"{'✅' if ok else '❌'} {esc(msg)}\n\n"
                "Роутер пропадёт ~30–60 сек. Обнови статус позже."
            )
            await reply_or_edit(update, text, kb([[btn("🔄 Обновить", f"r:{rid}")]]))

        elif act == "pres":
            ok, msg = await loop.run_in_executor(None, do_podkop_restart, r, ssh_cfg)
            result = "ok" if ok else f"fail: {msg}"
            log.info("podkop restart %s by %s -> %s", rid, u.id, result)
            db.audit(u.id, u.username, rid, "podkop_restart", None, result)
            text = (
                f"<b>{rid}</b> — Restart podkop\n\n"
                f"{'✅' if ok else '❌'}\n<pre>{esc(msg[:500])}</pre>"
            )
            await reply_or_edit(update, text, kb([[btn("🔄 Обновить", f"r:{rid}")]]))

        elif act == "check":
            ok_flag, full, _ = await loop.run_in_executor(None, do_global_check, r, ssh_cfg)
            # Сохранить полный лог
            runs_dir = Path(cfg["paths"]["runs"]) / rid
            runs_dir.mkdir(parents=True, exist_ok=True)
            ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            log_path = runs_dir / f"globalcheck-{ts}.log"
            log_path.write_text(full, encoding="utf-8")
            tail_lines = full.strip().splitlines()[-15:]
            verdict = "✅ OK" if ok_flag else "⚠️ проверь лог"
            size_kb = log_path.stat().st_size / 1024
            text = (
                f"<b>{rid}</b> — global_check\n\n"
                f"<pre>{esc(chr(10).join(tail_lines))[:1800]}</pre>\n"
                f"VERDICT: <b>{verdict}</b>\n"
                f"(лог {len(full.splitlines())} строк · {size_kb:.1f} KB)"
            )
            rows_kb = [
                [btn("📄 Полный лог", f"log:send:{rid}:{log_path.name}")],
                # Stage 3 / Client пкт 2: отправить лог админу
                [btn("📤 Отправить лог админу", f"lga:{rid}:{log_path.name}")],
                [btn("🔁 Повторить", f"act:{rid}:check"), btn("← назад", f"r:{rid}")],
            ]
            kb_ = kb(rows_kb)
            db.audit(u.id, u.username, rid, "global_check", None, verdict)
            await reply_or_edit(update, text, kb_)

        elif act == "info":
            out = await loop.run_in_executor(None, do_info, r, ssh_cfg)
            text = f"<b>{rid}</b> — info\n\n<pre>{esc(out[:3500])}</pre>"
            db.audit(u.id, u.username, rid, "info", None, "ok")
            await reply_or_edit(update, text, kb([[btn("← назад", f"r:{rid}")]]))

        elif act == "logs":
            out = await loop.run_in_executor(None, do_logread, r, ssh_cfg, 50)
            runs_dir = Path(cfg["paths"]["runs"]) / rid
            runs_dir.mkdir(parents=True, exist_ok=True)
            ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            log_path = runs_dir / f"logread-{ts}.log"
            log_path.write_text(out, encoding="utf-8")
            tail = "\n".join(out.strip().splitlines()[-15:])
            text = (
                f"<b>{rid}</b> — logread (последние 15 из 50)\n\n"
                f"<pre>{esc(tail)[:1800]}</pre>"
            )
            kb_ = kb(
                [
                    [btn("📄 Полный лог", f"log:send:{rid}:{log_path.name}")],
                    [btn("← назад", f"r:{rid}")],
                ]
            )
            db.audit(u.id, u.username, rid, "logs", None, "ok")
            await reply_or_edit(update, text, kb_)

        elif act == "plogs":
            out = await loop.run_in_executor(None, do_podkop_logs, r, ssh_cfg, 50)
            runs_dir = Path(cfg["paths"]["runs"]) / rid
            runs_dir.mkdir(parents=True, exist_ok=True)
            ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            log_path = runs_dir / f"podkoplogs-{ts}.log"
            log_path.write_text(out, encoding="utf-8")
            tail = "\n".join(out.strip().splitlines()[-15:])
            text = f"<b>{rid}</b> — podkop logs\n\n<pre>{esc(tail)[:1800]}</pre>"
            kb_ = kb(
                [
                    [btn("📄 Полный лог", f"log:send:{rid}:{log_path.name}")],
                    [btn("← назад", f"r:{rid}")],
                ]
            )
            db.audit(u.id, u.username, rid, "podkop_logs", None, "ok")
            await reply_or_edit(update, text, kb_)

    except Exception as e:
        log.exception("action %s on %s failed", act, rid)
        db.audit(u.id, u.username, rid, act, None, f"fail: {e}")
        await reply_or_edit(
            update,
            f"❌ Ошибка: <code>{esc(str(e))}</code>",
            kb([[btn("← назад", f"r:{rid}")]]),
        )


async def cb_log_send(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Отправить файл полного лога."""
    q = update.callback_query
    _, _, rid, fname = q.data.split(":", 3)
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    await q.answer()
    cfg: dict = ctx.application.bot_data["cfg"]
    path = Path(cfg["paths"]["runs"]) / rid / fname
    if not path.exists():
        await q.message.reply_text("Файл уже удалён (старше 30 дней?).")
        return
    with open(path, "rb") as f:
        await q.message.reply_document(
            document=InputFile(f, filename=f"{rid}-{fname}"),
            caption=f"{rid} / {fname}",
        )


# =============================================================================
# VLESS: выбор (клиент/admin)
# =============================================================================

VLESS_PAGE = 8


async def cb_vless_pick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid, page_s = q.data.split(":")
    page = int(page_s)
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return

    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    pool = db.vless_for_router(rid)
    st = db.get_state(rid)
    current = (st["active_vless"] or "") if st else ""

    if not pool:
        await reply_or_edit(
            update,
            f"<b>{rid}</b> — список серверов пуст.\n"
            "Обратись к администратору чтобы он добавил ссылки.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    start = page * VLESS_PAGE
    chunk = pool[start : start + VLESS_PAGE]

    # Определить «текущую» в пуле
    current_remark = "—"
    if current:
        for v in pool:
            if v["vless_url"] == current:
                current_remark = f"{v['remark']} ({v['host']})"
                break
        else:
            # есть своя, не из пула
            try:
                rm, hs = parse_vless(current)
                current_remark = f"{rm} ({hs}) — своя"
            except Exception:
                current_remark = "(неизвестная)"

    rows = []
    for v in chunk:
        lbl = f"{v['remark']} ({v['host']})"
        if v["vless_url"] == current:
            lbl = "● " + lbl
        rows.append([btn(lbl[:60], f"vless:conf:{rid}:{v['id']}")])

    nav = []
    if page > 0:
        nav.append(btn("←", f"vless:pick:{rid}:{page-1}"))
    if start + VLESS_PAGE < len(pool):
        nav.append(btn("→", f"vless:pick:{rid}:{page+1}"))
    if nav:
        rows.append(nav)
    rows.append([btn("← назад", f"r:{rid}")])

    text = (
        f"<b>{rid}</b> — выбор сервера\n"
        f"Сейчас: <b>{esc(current_remark)}</b>"
    )
    await reply_or_edit(update, text, kb(rows))


async def cb_vless_conf(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid, vid_s = q.data.split(":")
    vid = int(vid_s)
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    v = db.vless_by_id(vid)
    if not v:
        await q.answer("Ссылка удалена", show_alert=True)
        return
    text = (
        f"<b>{rid}</b> — сменить сервер\n\n"
        f"На: <b>{esc(v['remark'])}</b> (<code>{esc(v['host'])}</code>)\n\n"
        "Подкоп перезапустится, будет пауза ~5 сек."
    )
    await reply_or_edit(
        update,
        text,
        kb_confirm(f"vless:apply:{rid}:{vid}", f"vless:pick:{rid}:0"),
    )


async def cb_vless_apply(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid, vid_s = q.data.split(":")
    vid = int(vid_s)
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return

    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    # Stage 2 / A2: если на роутере выставлен custom VLESS — он вне пула,
    # ротация запрещена. Админ должен сначала «🔁 Вернуть в пул», и только
    # потом сможет менять через стандартный flow.
    st = db.get_state(rid)
    if st is not None:
        try:
            cv = st["custom_vless_url"]
        except (IndexError, KeyError):
            cv = None
        if cv:
            await reply_or_edit(
                update,
                f"<b>{rid}</b> на custom VLESS — ротация из пула заблокирована.\n\n"
                "Чтобы вернуться к стандартному пулу, нажми «🔁 Вернуть в пул» в меню роутера.",
                kb([[btn("← назад", f"r:{rid}")]]),
            )
            return

    # rate limit
    role = user_role(ctx, u.id)
    if role != "admin":
        limit = cfg["rate_limits"].get("vless_change_per_day", 0)
        if limit > 0 and not db.rate_check_and_inc(u.id, "vless", limit):
            await reply_or_edit(
                update,
                "Лимит смен VLESS на сегодня исчерпан.",
                kb([[btn("← назад", f"r:{rid}")]]),
            )
            return

    v = db.vless_by_id(vid)
    if not v:
        await reply_or_edit(update, "Ссылка удалена.", kb([[btn("← назад", f"r:{rid}")]]))
        return

    r = router_by_id(ctx, rid)
    if r is None:
        db.audit(u.id, u.username, rid, "vless_change", v["remark"], "fail: offline")
        await reply_or_edit(
            update,
            f"{rid} offline — смена невозможна.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    await reply_or_edit(update, f"Применяю {v['remark']} на {rid}…")

    loop = asyncio.get_event_loop()
    ok, msg = await loop.run_in_executor(None, do_set_vless, r, rcfg["ssh"], v["vless_url"], True)
    result = "ok" if ok else f"fail: {msg}"
    log.info("vless change %s -> id=%d by %s -> %s", rid, vid, u.id, result)
    db.audit(u.id, u.username, rid, "vless_change", f"{v['remark']}|id={vid}", result)

    if ok:
        text = (
            f"<b>{rid}</b> ✅\n\n"
            f"Активный сервер: <b>{esc(v['remark'])}</b>\n"
            f"Подкоп перезапущен. Нажми ▶️ чтобы проверить."
        )
    else:
        text = f"<b>{rid}</b> ❌\n<pre>{esc(msg[:800])}</pre>"
    await reply_or_edit(
        update,
        text,
        kb([[btn("▶️ Проверить", f"act:{rid}:check"), btn("← назад", f"r:{rid}")]]),
    )


# =============================================================================
# Stage 2 / A2: Custom VLESS — ввод вручную, выход из пула, возврат в пул
# =============================================================================
# Поток:
#   1. Админ жмёт «🔧 Custom VLESS»  (cb_vless_custom_start)
#   2. Бот переводит user_data в state="awaiting_custom_vless" с rid в state_rid
#   3. Текстовый handler парсит/валидирует, кладёт url+rid в user_data
#      и показывает двойное подтверждение (cb_vless_custom_confirm)
#   4. На «✅ Применить» — SSH set + db.set_custom_vless + audit
#   5. Возврат в пул: «🔁 Вернуть в пул» (cb_vless_pool_return) — двойное
#      подтверждение, db.set_custom_vless(rid, None), in_pool=1.
#      На роутер ничего не пишем — следующий пик из пула применит ключ.

async def cb_vless_custom_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await reply_or_edit(update, "Только админ.", kb([[btn("← назад", f"r:{rid}")]]))
        return
    ctx.user_data["state"] = "awaiting_custom_vless"
    ctx.user_data["state_rid"] = rid
    await reply_or_edit(
        update,
        f"<b>{rid}</b> — Custom VLESS\n\n"
        "Пришли строку <code>vless://...</code> с reality-параметрами "
        "(security=reality, pbk=..., sni=...).\n\n"
        "После применения роутер выйдет из пула ротации.\n"
        "Чтобы отменить — /cancel или нажми ниже.",
        kb([[btn("← Отмена", f"r:{rid}")]]),
    )


async def cb_vless_custom_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Применить custom VLESS — пользователь нажал «✅ Применить»."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    url = ctx.user_data.pop("pending_custom_vless_url", None)
    expected_rid = ctx.user_data.pop("pending_custom_vless_rid", None)
    if not url or expected_rid != rid:
        await reply_or_edit(
            update,
            "Сессия истекла. Начни заново.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    r = router_by_id(ctx, rid)
    if r is None:
        db.audit(u.id, u.username, rid, "vless_custom_apply",
                 mask_vless_for_audit(url), "fail: offline")
        await reply_or_edit(
            update,
            f"{rid} offline — применение невозможно. Custom URL не сохранён.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    await reply_or_edit(update, f"Применяю custom VLESS на {rid}…")
    loop = asyncio.get_event_loop()
    ok, msg = await loop.run_in_executor(None, do_set_vless, r, rcfg["ssh"], url, True)
    masked = mask_vless_for_audit(url)
    if ok:
        db.set_custom_vless(rid, url)
        db.audit(u.id, u.username, rid, "vless_custom_apply", masked, "ok")
        log.info("custom vless on %s by %s -> ok", rid, u.id)
        text = (
            f"<b>{rid}</b> ✅\n\nCustom VLESS применён, роутер выведен из пула.\n"
            f"Маска для audit: <code>{esc(masked)}</code>"
        )
    else:
        db.audit(u.id, u.username, rid, "vless_custom_apply", masked, f"fail: {msg}")
        text = (
            f"<b>{rid}</b> ❌\n\nНе удалось применить custom VLESS:\n"
            f"<pre>{esc(msg[:500])}</pre>\n\nИзменения не сохранены."
        )
    await reply_or_edit(
        update,
        text,
        kb([
            [btn("▶️ Проверить", f"act:{rid}:check")],
            [btn("← назад", f"r:{rid}")],
        ]),
    )


async def cb_vless_pool_return(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Вернуть роутер в пул — снять custom_vless_url, in_pool=1.
    На роутер ничего не пишем; админ потом сам выберет новый ключ из пула
    через стандартный «🔗 Сменить VLESS»."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await reply_or_edit(update, "Только админ.", kb([[btn("← назад", f"r:{rid}")]]))
        return
    db: DB = ctx.application.bot_data["db"]
    log = ctx.application.bot_data["log"]
    db.set_custom_vless(rid, None)
    db.audit(u.id, u.username, rid, "vless_custom_clear", None, "ok")
    log.info("custom vless cleared on %s by %s", rid, u.id)
    await reply_or_edit(
        update,
        f"<b>{rid}</b> ✅\n\nCustom VLESS снят, роутер вернулся в пул ротации.\n"
        "На самом роутере текущий URL остался прежним — выбери новый из пула, "
        "если нужно сменить.",
        kb([
            [btn("🔗 Сменить VLESS", f"vless:pick:{rid}:0")],
            [btn("← назад", f"r:{rid}")],
        ]),
    )


# =============================================================================
# Stage 2 / клиентский пункт 7 + админ: WiFi-меню
# =============================================================================
# Поток:
#   1. cb_wifi_menu — читает по SSH (или из снапшота если оффлайн), показывает
#      SSID и маскированный пароль; для админа кнопка «👁 Показать пароль».
#   2. cb_wifi_edit_start — переводит state="awaiting_wifi_ssid", rid
#   3. text handler ssid → state="awaiting_wifi_pwd"
#   4. text handler pwd → cb_wifi_edit_confirm с двойным подтверждением
#   5. cb_wifi_edit_apply — do_set_wifi + audit (без пароля) + лимит 5/день клиенту

async def cb_wifi_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await reply_or_edit(update, "Нет доступа.", kb([[btn("← Главная", "menu:main")]]))
        return

    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    role = user_role(ctx, u.id)
    is_admin_user = (role == "admin")

    # Stage 2 / A1: на maintenance/transit клиент не должен править WiFi.
    st = db.get_state(rid)
    lifecycle = _row_lifecycle(st)
    if lifecycle in ("transit", "maintenance") and not is_admin_user:
        await reply_or_edit(
            update,
            f"<b>{rid}</b>\n\n🛠 Сейчас идут техработы, WiFi-настройки недоступны.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    # Пробуем прочитать актуальные настройки. Если оффлайн — берём snapshot.
    r = router_by_id(ctx, rid)
    info_ssid = ""
    info_enc = ""
    info_key = ""
    note = ""
    source = "live"
    if r is not None:
        await reply_or_edit(update, f"<b>{rid}</b> — читаю WiFi-настройки…")
        loop = asyncio.get_event_loop()
        try:
            wi = await loop.run_in_executor(None, do_get_wifi, r, rcfg["ssh"])
            if wi.error:
                source = "snapshot"
                note = f"⚠ ошибка чтения: {wi.error[:80]}"
            else:
                info_ssid = wi.ssid
                info_enc = wi.encryption
                info_key = wi.key
                note = wi.note
                # Освежим снапшот в БД.
                db.set_wifi_snapshot(rid, info_ssid or None, info_enc or None)
        except Exception as e:
            source = "snapshot"
            note = f"⚠ исключение: {e}"
    else:
        source = "snapshot"
        note = "роутер offline, показываю последний снапшот"
    if source == "snapshot":
        try:
            info_ssid = (st["wifi_ssid"] if st else "") or ""
            info_enc = (st["wifi_encryption"] if st else "") or ""
        except (IndexError, KeyError):
            pass

    masked = ("•" * min(len(info_key), 12)) if info_key else "(скрыто)"
    enc_display = info_enc or "WPA2-PSK"
    lines = [
        f"📶 <b>WiFi настройки {rid}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Сеть: <b>{esc(info_ssid) if info_ssid else '(не задано)'}</b>",
    ]
    if is_admin_user and info_key:
        lines.append(f"Пароль: <code>{esc(masked)}</code>")
    else:
        lines.append(f"Пароль: <code>{masked}</code>")
    lines.append(f"Шифрование: {esc(enc_display)}")
    if note:
        lines.append(f"\n<i>{esc(note)}</i>")
    if source == "snapshot":
        lines.append("<i>(показан снапшот, роутер недоступен — изменение запрещено)</i>")

    rows: list = []
    if is_admin_user and info_key and source == "live":
        rows.append([btn("👁 Показать пароль (admin)", f"wifi:show:{rid}")])
    if source == "live":
        rows.append([btn("✏️ Изменить", f"wifi:edit:{rid}")])
    rows.append([btn("← назад", f"r:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_wifi_show_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Только админ: показать пароль явно (с предупреждением, audit)."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    r = router_by_id(ctx, rid)
    if r is None:
        await reply_or_edit(update, f"{rid} offline.", kb([[btn("← назад", f"wifi:menu:{rid}")]]))
        return
    await reply_or_edit(update, "Читаю пароль…")
    loop = asyncio.get_event_loop()
    wi = await loop.run_in_executor(None, do_get_wifi, r, rcfg["ssh"])
    if wi.error:
        await reply_or_edit(
            update, f"❌ {esc(wi.error)}",
            kb([[btn("← назад", f"wifi:menu:{rid}")]]),
        )
        return
    db.audit(u.id, u.username, rid, "wifi_password_view", None, "ok")
    text = (
        f"📶 <b>{rid}</b> — пароль (admin view)\n"
        f"SSID: <code>{esc(wi.ssid)}</code>\n"
        f"Пароль: <code>{esc(wi.key)}</code>\n\n"
        "<i>Этот просмотр записан в audit-лог.</i>"
    )
    await reply_or_edit(
        update, text,
        kb([[btn("← назад", f"wifi:menu:{rid}")]]),
    )


async def cb_wifi_edit_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    ctx.user_data["state"] = "awaiting_wifi_ssid"
    ctx.user_data["state_rid"] = rid
    await reply_or_edit(
        update,
        f"📶 <b>{rid}</b> — изменить WiFi\n\n"
        "Шаг 1/2: пришли новое имя сети (SSID), 1–32 символа.\n\n"
        "/cancel чтобы отменить.",
        kb([[btn("← Отмена", f"wifi:menu:{rid}")]]),
    )


async def cb_wifi_edit_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Применить WiFi — пользователь нажал «✅ Применить»."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    new_ssid = ctx.user_data.pop("pending_wifi_ssid", None)
    new_pwd = ctx.user_data.pop("pending_wifi_pwd", None)
    expected_rid = ctx.user_data.pop("pending_wifi_rid", None)
    if not new_ssid or not new_pwd or expected_rid != rid:
        await reply_or_edit(
            update, "Сессия истекла. Начни заново.",
            kb([[btn("← назад", f"wifi:menu:{rid}")]]),
        )
        return
    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]
    role = user_role(ctx, u.id)

    # Лимит для клиента: 5 в сутки. Админу — без лимита.
    if role != "admin":
        limit = cfg["rate_limits"].get("wifi_change_per_day", 5)
        if limit > 0 and not db.rate_check_and_inc(u.id, "wifi_change", limit):
            await reply_or_edit(
                update,
                f"Лимит смен WiFi на сегодня исчерпан ({limit}/день). Попробуй завтра.",
                kb([[btn("← назад", f"wifi:menu:{rid}")]]),
            )
            return

    r = router_by_id(ctx, rid)
    if r is None:
        db.audit(u.id, u.username, rid, "wifi_change", None, "fail: offline")
        await reply_or_edit(
            update, f"{rid} offline — изменение невозможно.",
            kb([[btn("← назад", f"wifi:menu:{rid}")]]),
        )
        return

    # Прочитаем старый ssid для audit (пароль НЕ пишем).
    old_ssid = ""
    try:
        cur = db.get_state(rid)
        old_ssid = (cur["wifi_ssid"] if cur else "") or ""
    except (IndexError, KeyError):
        old_ssid = ""

    await reply_or_edit(update, f"Применяю WiFi на {rid}…")
    loop = asyncio.get_event_loop()
    ok, msg = await loop.run_in_executor(
        None, do_set_wifi, r, rcfg["ssh"], new_ssid, new_pwd
    )
    args_audit = json.dumps({"ssid_before": old_ssid, "ssid_after": new_ssid},
                            ensure_ascii=False)
    if ok:
        db.set_wifi_snapshot(rid, new_ssid, "psk2")
        db.audit(u.id, u.username, rid, "wifi_change", args_audit, "ok")
        try:
            db.add_wifi_history(rid, old_ssid, new_ssid, u.id)
        except Exception:
            log.exception("wifi_history")
        log.info("wifi change %s by %s -> ok (ssid=%s)", rid, u.id, new_ssid)
        # Stage 3 / A6: push админу, если менял клиент.
        try:
            if role != "admin":
                await _push_admins(
                    ctx,
                    f"📶 <b>{rid}</b> (@{esc(u.username or u.first_name or u.id)}): "
                    f"сменён WiFi\n"
                    f"SSID: <code>{esc(old_ssid or '—')}</code> → <code>{esc(new_ssid)}</code>",
                    kb([[btn("📜 История", f"aud:r:{rid}:0")]]),
                )
        except Exception:
            log.exception("push admin wifi")
        text = (
            f"<b>{rid}</b> ✅\n\nWiFi обновлён. Все устройства должны переподключиться "
            f"с новым паролем.\n\nНовая сеть: <b>{esc(new_ssid)}</b>"
        )
    else:
        db.audit(u.id, u.username, rid, "wifi_change", args_audit, f"fail: {msg}")
        text = f"<b>{rid}</b> ❌\n\n<pre>{esc(msg[:500])}</pre>"
    await reply_or_edit(
        update, text,
        kb([
            [btn("📶 К WiFi-меню", f"wifi:menu:{rid}")],
            [btn("← назад", f"r:{rid}")],
        ]),
    )


# =============================================================================
# Stage 2 / A9: admin owners management UI
# =============================================================================
# Модель: связка клиент↔роутер хранится в таблице bindings (N:N).
# Админ может добавить (@username или tg_id) и снять владельца.
# Кнопка «👥 Владельцы» в меню роутера → cb_owners_list.

async def cb_owners_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    owners = db.router_clients(rid)
    lines = [f"👥 <b>{rid}</b> — владельцы"]
    if not owners:
        lines.append("\n<i>(нет привязанных клиентов)</i>")
    else:
        lines.append("")
        for c in owners:
            try:
                uname = c["username"] or ""
                fname = c["first_name"] or ""
                tgid = c["tg_id"]
                role = c["role"] or "client"
            except (IndexError, KeyError):
                continue
            who = f"@{esc(uname)}" if uname else esc(fname or str(tgid))
            tag = "👑" if role == "admin" else "👤"
            lines.append(f"{tag} {who} · <code>{tgid}</code>")
    rows: list = [[btn("➕ Добавить владельца", f"own:add:{rid}")]]
    for c in owners:
        try:
            uname = c["username"] or ""
            fname = c["first_name"] or ""
            tgid = c["tg_id"]
        except (IndexError, KeyError):
            continue
        short = f"@{uname}" if uname else (fname or str(tgid))
        if len(short) > 20:
            short = short[:19] + "…"
        rows.append([btn(f"✖ {short}", f"own:rm:{rid}:{tgid}")])
    rows.append([btn("← к роутеру", f"r:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_owner_add_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    ctx.user_data["state"] = "awaiting_owner_add"
    ctx.user_data["state_rid"] = rid
    await reply_or_edit(
        update,
        f"👥 <b>{rid}</b> — добавить владельца\n\n"
        "Пришли <code>@username</code> или числовой <code>tg_id</code>.\n\n"
        "⚠ Клиент должен уже существовать в БД (нажимал /start). "
        "Если его нет — попроси запустить бота, потом вернись сюда.\n\n"
        "/cancel чтобы отменить.",
        kb([[btn("← Отмена", f"own:list:{rid}")]]),
    )


async def cb_owner_remove(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    parts = q.data.split(":")
    # own:rm:<rid>:<tg_id>
    if len(parts) != 4:
        await q.answer("bad callback", show_alert=True)
        return
    _, _, rid, tgid_s = parts
    try:
        tgid = int(tgid_s)
    except ValueError:
        await q.answer("bad tg_id", show_alert=True)
        return
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    cli = db.get_client(tgid)
    try:
        uname = (cli["username"] if cli else "") or ""
    except (IndexError, KeyError):
        uname = ""
    try:
        db.unbind(tgid, rid)
        db.audit(u.id, u.username, rid, "owner_remove",
                 f"tg_id={tgid} @{uname or '—'}", "ok")
        await cb_owners_list(update, ctx)
    except Exception as e:
        log = ctx.application.bot_data.get("log")
        if log:
            log.exception("owner_remove")
        await reply_or_edit(update, f"❌ {esc(e)}",
                            kb([[btn("← назад", f"own:list:{rid}")]]))


# =============================================================================
# Stage 3 / Клиент пкт 8: Маршрутизация (user_domains)
# =============================================================================
# Меню: cb_rt_menu → рисует список + кнопки [➕ Добавить] [✏ Убрать] [✅ Применить]
# Flow:
#   ➕ Добавить → state=awaiting_routing_add (rid); text-handler принимает
#      по одному или столбиком домены, валидирует, кладёт в pending_routing.added.
#   ✏ Убрать → cb_rt_remove_list (страница по 10, каждая кнопка — домен).
#      Клик по домену → убирает из effective или добавляет в removed.
#   ✅ Применить → diff preview → kb_confirm → cb_rt_apply.
# Лимиты для клиента: 20 add/день, 20 del/день, итог ≤ 200 доменов.

RT_PAGE_SIZE = 10


async def _rt_current_state(db: DB, rid: str, ctx: ContextTypes.DEFAULT_TYPE,
                            tg_id: int) -> tuple[bool, list[str], list[str],
                                                  list[str], str]:
    """Возвращает (ok, server_list, added, removed, err).

    server_list — что сейчас на роутере (uci get).
    added — JSON pending.added_json (не применённые добавления).
    removed — JSON pending.removed_json (не применённые удаления)."""
    rcfg: dict = ctx.application.bot_data["r_config"]
    r = router_by_id(ctx, rid)
    if r is None:
        return False, [], [], [], "роутер offline"
    loop = asyncio.get_event_loop()
    ok, domains, err = await loop.run_in_executor(
        None, do_get_routing, r, rcfg["ssh"]
    )
    if not ok:
        return False, [], [], [], err
    added: list[str] = []
    removed: list[str] = []
    pend = db.pending_routing_get(tg_id, rid)
    if pend is not None:
        try:
            added = json.loads(pend["added_json"] or "[]")
        except (json.JSONDecodeError, TypeError):
            added = []
        try:
            removed = json.loads(pend["removed_json"] or "[]")
        except (json.JSONDecodeError, TypeError):
            removed = []
    return True, domains, added, removed, ""


def _rt_effective(server: list[str], added: list[str],
                  removed: list[str]) -> list[str]:
    """Эффективный список после применения: server − removed + added (без дублей)."""
    present = {d.lower() for d in server}
    rm = {d.lower() for d in removed}
    result = [d for d in server if d.lower() not in rm]
    for d in added:
        if d.lower() not in present:
            result.append(d)
    return result


async def cb_rt_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await reply_or_edit(update, "Нет доступа.",
                            kb([[btn("← Главная", "menu:main")]]))
        return

    db: DB = ctx.application.bot_data["db"]
    # Проверка lifecycle
    st = db.get_state(rid)
    lifecycle = _row_lifecycle(st)
    role = user_role(ctx, u.id)
    is_admin_user = (role == "admin")
    if lifecycle in ("transit", "maintenance") and not is_admin_user:
        await reply_or_edit(
            update,
            f"<b>{rid}</b>\n\n🛠 Сейчас идут техработы, маршрутизация недоступна.",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    await reply_or_edit(update, f"<b>{rid}</b> — читаю список доменов…")
    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(
            update, f"<b>{rid}</b> ❌\n<pre>{esc(err[:300])}</pre>",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return
    effective = _rt_effective(server, added, removed)

    lines = [
        f"📋 <b>Маршрутизация {rid}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"На роутере сейчас: <b>{len(server)}</b>",
    ]
    if added or removed:
        lines.append(
            f"Pending: ➕{len(added)} / ➖{len(removed)} "
            f"→ итог <b>{len(effective)}</b>"
        )
    if len(effective) > 200:
        lines.append("⚠ итог превышает 200 — для клиента отказ при apply")
    lines.append("")
    if not effective:
        lines.append("<i>(список пуст — маршрутизация отключена)</i>")
    else:
        # Показываем первые 30 (до переполнения сообщения TG)
        display = effective[:30]
        for i, d in enumerate(display, 1):
            tag = ""
            dl = d.lower()
            if dl in (a.lower() for a in added):
                tag = "  <i>(pending ➕)</i>"
            lines.append(f"{i}. <code>{esc(d)}</code>{tag}")
        if len(effective) > 30:
            lines.append(f"… ещё {len(effective) - 30} доменов")

    rows: list = []
    rows.append([
        btn("➕ Добавить", f"rt:add:{rid}"),
        btn("✏ Убрать", f"rt:rmlist:{rid}:0"),
    ])
    if added or removed:
        rows.append([
            btn("✅ Применить", f"rt:preview:{rid}"),
            btn("♻ Сбросить правки", f"rt:reset:{rid}"),
        ])
    rows.append([btn("🔄 Обновить", f"rt:menu:{rid}")])
    rows.append([btn("← назад", f"r:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_rt_add_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    ctx.user_data["state"] = "awaiting_routing_add"
    ctx.user_data["state_rid"] = rid
    await reply_or_edit(
        update,
        f"📋 <b>{rid}</b> — добавить домены\n\n"
        "Пришли один домен или список столбиком (по одному на строку).\n\n"
        "Только латиница+цифры+дефис, без <code>http://</code>, "
        "<code>www.</code>, портов, путей и IP.\n\n"
        "Например:\n"
        "<code>youtube.com\nchatgpt.com\n2ip.ru</code>\n\n"
        "/cancel чтобы отменить.",
        kb([[btn("← Отмена", f"rt:menu:{rid}")]]),
    )


async def cb_rt_remove_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Список доменов с кнопками для удаления. Клик — добавить в removed."""
    q = update.callback_query
    parts = q.data.split(":")
    # rt:rmlist:<rid>:<page>
    _, _, rid, page_s = parts
    page = int(page_s)
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(
            update, f"❌ {esc(err)}",
            kb([[btn("← назад", f"rt:menu:{rid}")]]),
        )
        return
    effective = _rt_effective(server, added, removed)
    if not effective:
        await reply_or_edit(
            update, f"<b>{rid}</b>\n\n<i>(список пуст)</i>",
            kb([[btn("← назад", f"rt:menu:{rid}")]]),
        )
        return
    start = page * RT_PAGE_SIZE
    chunk = effective[start : start + RT_PAGE_SIZE]
    total_pages = (len(effective) + RT_PAGE_SIZE - 1) // RT_PAGE_SIZE

    lines = [
        f"📋 <b>{rid}</b> — нажми на домен чтобы убрать",
        f"Стр. {page + 1}/{total_pages}",
        "",
    ]
    rows: list = []
    for i, d in enumerate(chunk, start=start + 1):
        tag = " pending-add" if d in added else ""
        lines.append(f"{i}. <code>{esc(d)}</code>{tag}")
        rows.append([btn(f"✖ {d[:40]}", f"rt:rmone:{rid}:{start + i - start - 1}")])
        # Индекс domain'а внутри effective[] для rt:rmone.
    # Переделаем: проще и честнее передать сам домен, но callback_data ограничен
    # 64 байтами. Для длинных доменов fallback на индекс.
    rows = []
    for i, d in enumerate(chunk):
        # Пытаемся передать сам домен, урезая до 45 символов под callback-лимит
        # (префикс «rt:rmone:idNNN:» занимает ~15 байт).
        cb = f"rt:rmone:{rid}:{d}"
        if len(cb.encode("utf-8")) > 64:
            # Слишком длинный — кодируем индекс в effective.
            global_idx = start + i
            cb = f"rt:rmoneI:{rid}:{global_idx}"
        rows.append([btn(f"✖ {d[:40]}", cb)])
    # Пагинация
    pager: list = []
    if page > 0:
        pager.append(btn("‹", f"rt:rmlist:{rid}:{page - 1}"))
    pager.append(btn(f"{page + 1}/{total_pages}", "noop"))
    if page + 1 < total_pages:
        pager.append(btn("›", f"rt:rmlist:{rid}:{page + 1}"))
    if pager:
        rows.append(pager)
    rows.append([btn("← назад", f"rt:menu:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_rt_rmone(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Убрать один домен (из добавленного — снять, из server — добавить в removed)."""
    q = update.callback_query
    parts = q.data.split(":", 3)
    # rt:rmone:<rid>:<domain>  или  rt:rmoneI:<rid>:<idx>
    if len(parts) != 4:
        await q.answer("bad callback", show_alert=True)
        return
    _, mode, rid, payload = parts
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(update, f"❌ {esc(err)}",
                            kb([[btn("← назад", f"rt:menu:{rid}")]]))
        return
    effective = _rt_effective(server, added, removed)
    if mode == "rmoneI":
        try:
            idx = int(payload)
            domain = effective[idx]
        except (ValueError, IndexError):
            await q.answer("не найден", show_alert=True)
            return
    else:
        domain = payload
    if domain not in effective:
        await q.answer("уже удалён", show_alert=False)
    else:
        # Rate-limit для клиента (кроме admin): считаем «удаления».
        cfg: dict = ctx.application.bot_data["cfg"]
        role = user_role(ctx, u.id)
        if role != "admin":
            limit = cfg["rate_limits"].get("routing_del_per_day", 20)
            if limit > 0 and not db.rate_check_and_inc(u.id, "routing_del", limit):
                await q.answer(f"Лимит {limit}/день", show_alert=True)
                await cb_rt_menu_redraw(update, ctx, rid)
                return
        # Если домен был в server — кладём в removed; если был в added — снимаем.
        dl = domain.lower()
        if any(a.lower() == dl for a in added):
            added = [a for a in added if a.lower() != dl]
        else:
            if not any(r.lower() == dl for r in removed):
                removed.append(domain)
        db.pending_routing_save(u.id, rid, added, removed)
    await cb_rt_menu_redraw(update, ctx, rid)


async def cb_rt_menu_redraw(update: Update, ctx: ContextTypes.DEFAULT_TYPE, rid: str):
    """Перерисовать главное меню rt после правки."""
    # Переиспользуем cb_rt_menu, подменив callback_data на q.
    q = update.callback_query
    # Эмулируем q.data = "rt:menu:rid"
    class _FakeQ:
        data = f"rt:menu:{rid}"
    # Чисто: просто вызываем handler, но q уже у нас есть — меняем data обходом:
    # Проще — вызвать функцию с прямым rid. Сделаем так: просто продублируем логику.
    u = update.effective_user
    db: DB = ctx.application.bot_data["db"]
    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(update, f"❌ {esc(err)}",
                            kb([[btn("← назад", f"r:{rid}")]]))
        return
    effective = _rt_effective(server, added, removed)
    lines = [
        f"📋 <b>Маршрутизация {rid}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"На роутере: <b>{len(server)}</b>",
    ]
    if added or removed:
        lines.append(f"Pending: ➕{len(added)} / ➖{len(removed)} → итог <b>{len(effective)}</b>")
    if len(effective) > 200:
        lines.append("⚠ итог > 200")
    rows = [[
        btn("➕ Добавить", f"rt:add:{rid}"),
        btn("✏ Убрать", f"rt:rmlist:{rid}:0"),
    ]]
    if added or removed:
        rows.append([
            btn("✅ Применить", f"rt:preview:{rid}"),
            btn("♻ Сбросить правки", f"rt:reset:{rid}"),
        ])
    rows.append([btn("🔄 Обновить", f"rt:menu:{rid}")])
    rows.append([btn("← назад", f"r:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_rt_reset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    db.pending_routing_clear(u.id, rid)
    await q.answer("Pending-правки сброшены")
    await cb_rt_menu_redraw(update, ctx, rid)


async def cb_rt_preview(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Показать diff и кнопку Применить."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(update, f"❌ {esc(err)}",
                            kb([[btn("← назад", f"rt:menu:{rid}")]]))
        return
    effective = _rt_effective(server, added, removed)
    cfg: dict = ctx.application.bot_data["cfg"]
    role = user_role(ctx, u.id)
    max_domains = cfg.get("routing_max_domains", 200)
    if role != "admin" and len(effective) > max_domains:
        await reply_or_edit(
            update,
            f"❌ <b>{rid}</b>: итог будет <b>{len(effective)}</b> доменов, "
            f"максимум <b>{max_domains}</b>.\n"
            "Снимай часть добавлений или удаляй лишнее.",
            kb([[btn("← назад", f"rt:menu:{rid}")]]),
        )
        return
    if not added and not removed:
        await reply_or_edit(
            update, "Нечего применять.",
            kb([[btn("← назад", f"rt:menu:{rid}")]]),
        )
        return

    lines = [f"📋 <b>{rid}</b> — подтверди изменения", ""]
    if added:
        lines.append(f"➕ <b>Добавить ({len(added)}):</b>")
        for d in added[:20]:
            lines.append(f"   <code>{esc(d)}</code>")
        if len(added) > 20:
            lines.append(f"   … ещё {len(added) - 20}")
        lines.append("")
    if removed:
        lines.append(f"➖ <b>Убрать ({len(removed)}):</b>")
        for d in removed[:20]:
            lines.append(f"   <code>{esc(d)}</code>")
        if len(removed) > 20:
            lines.append(f"   … ещё {len(removed) - 20}")
        lines.append("")
    lines.append(f"Итоговый размер: <b>{len(effective)}</b>")
    lines.append("")
    lines.append("⚠ После применения служба перезапустится, интернет моргнёт 5–10 сек.")
    await reply_or_edit(
        update, "\n".join(lines),
        kb([
            [btn("✅ Применить", f"rt:apply:{rid}"),
             btn("✖ Отмена", f"rt:menu:{rid}")],
        ]),
    )


async def cb_rt_apply(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
    if not ok:
        await reply_or_edit(update, f"❌ {esc(err)}",
                            kb([[btn("← назад", f"rt:menu:{rid}")]]))
        return
    if not added and not removed:
        await reply_or_edit(update, "Нечего применять.",
                            kb([[btn("← назад", f"rt:menu:{rid}")]]))
        return
    r = router_by_id(ctx, rid)
    if r is None:
        db.audit(u.id, u.username, rid, "routing_apply", None, "fail: offline")
        await reply_or_edit(update, f"{rid} offline — применение невозможно.",
                            kb([[btn("← назад", f"rt:menu:{rid}")]]))
        return

    await reply_or_edit(update, f"Применяю маршрутизацию на {rid}…")
    loop = asyncio.get_event_loop()
    ok2, msg = await loop.run_in_executor(
        None, do_set_routing, r, rcfg["ssh"], added, removed
    )
    payload = json.dumps({"added": added, "removed": removed,
                          "size_after": len(_rt_effective(server, added, removed))},
                         ensure_ascii=False)
    if ok2:
        db.pending_routing_clear(u.id, rid)
        db.audit(u.id, u.username, rid, "routing_apply", payload, "ok")
        log.info("routing_apply %s by %s -> ok", rid, u.id)
        # Stage 3 / A6: push админу, если менял клиент.
        try:
            if user_role(ctx, u.id) != "admin":
                await _push_admins(
                    ctx,
                    f"⚙ <b>{rid}</b> (@{esc(u.username or u.first_name or u.id)}): "
                    f"обновлена маршрутизация\n"
                    f"+{len(added)} / −{len(removed)} (итог {len(_rt_effective(server, added, removed))})",
                    kb([[btn("📜 История", f"aud:r:{rid}:0")]]),
                )
        except Exception:
            log.exception("push admin routing")
        text = (
            f"<b>{rid}</b> ✅\n\nМаршрутизация обновлена.\n"
            f"Добавлено: {len(added)} · убрано: {len(removed)}."
        )
    else:
        db.audit(u.id, u.username, rid, "routing_apply", payload, f"fail: {msg}")
        text = f"<b>{rid}</b> ❌\n<pre>{esc(msg[:500])}</pre>"
    await reply_or_edit(
        update, text,
        kb([
            [btn("📋 К меню", f"rt:menu:{rid}")],
            [btn("← к роутеру", f"r:{rid}")],
        ]),
    )


# =============================================================================
# Stage 3 / Клиент пкт 2: отправить лог админу
# =============================================================================

async def cb_log_to_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Клиент нажимает «📤 Отправить лог админу» после global check.
    Формат callback: `lga:<rid>:<fname>` — fname — имя файла в runs/ с
    глобальным check."""
    q = update.callback_query
    parts = q.data.split(":", 2)
    if len(parts) != 3:
        await q.answer("bad callback", show_alert=True)
        return
    _, rid, fname = parts
    u = update.effective_user
    if not u or not client_owns_router(ctx, u.id, rid):
        await q.answer("Нет доступа", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    role = user_role(ctx, u.id)
    # Лимит клиенту 5/день (админ не отправляет — кнопка ему и так не показывается)
    if role != "admin":
        limit = cfg["rate_limits"].get("send_log_per_day", 5)
        if limit > 0 and not db.rate_check_and_inc(u.id, "send_log", limit):
            await reply_or_edit(
                update,
                f"❌ Лимит {limit}/день исчерпан, вернись завтра или "
                "попроси админа связаться с тобой.",
                kb([[btn("← назад", f"r:{rid}")]]),
            )
            return

    # Собираем лог
    await reply_or_edit(update, f"<b>{rid}</b> — собираю лог для админа…")
    base_log = ""
    check_path = Path(cfg["paths"]["runs"]) / rid / fname
    if check_path.exists() and check_path.is_file():
        try:
            base_log = check_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            base_log = ""
    r = router_by_id(ctx, rid)
    full_body = ""
    if r is not None:
        loop = asyncio.get_event_loop()
        try:
            full_body = await loop.run_in_executor(
                None, do_capture_client_log, r, rcfg["ssh"], base_log
            )
        except Exception as e:
            full_body = f"(capture failed: {e})\n\n{base_log}"
    else:
        full_body = (
            "(роутер offline — прикрепляю только вывод global_check)\n\n"
            + base_log
        )

    # Сохраняем файл
    client_logs_dir = Path(cfg["paths"]["client_logs"]) / rid
    try:
        client_logs_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log.exception("mkdir client_logs")
        await reply_or_edit(
            update, f"❌ Не могу записать файл: {esc(e)}",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return
    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    fpath = client_logs_dir / f"log_{rid}_{ts}.txt"
    try:
        fpath.write_text(full_body, encoding="utf-8")
    except Exception as e:
        log.exception("write client log")
        await reply_or_edit(
            update, f"❌ Не могу записать файл: {esc(e)}",
            kb([[btn("← назад", f"r:{rid}")]]),
        )
        return

    preview_lines = full_body.strip().splitlines()[:5]
    preview = "\n".join(preview_lines)[:500]
    log_id = db.add_client_log(u.id, u.username, rid, str(fpath), preview)
    db.audit(u.id, u.username, rid, "send_log_to_admin",
             f"log_id={log_id} size={len(full_body)}", "ok")
    log.info("client log %s: %s -> %s", log_id, u.id, fpath)

    # Пуш админу с файлом + превью
    caption = (
        f"🆘 <b>Лог от клиента</b>\n"
        f"Роутер: <b>{rid}</b>\n"
        f"Клиент: @{esc(u.username or u.first_name or u.id)} "
        f"(<code>{u.id}</code>)\n\n"
        f"Превью:\n<pre>{esc(preview)[:600]}</pre>"
    )
    try:
        targets = _admin_chat_ids(ctx)
        for admin_id in targets:
            try:
                with open(fpath, "rb") as fh:
                    await ctx.bot.send_document(
                        admin_id,
                        document=InputFile(fh, filename=fpath.name),
                        caption=caption,
                        parse_mode=ParseMode.HTML,
                        reply_markup=kb([
                            [btn("👁 Прочитано", f"clog:read:{log_id}")],
                            [btn("📜 Аудит роутера", f"aud:r:{rid}:0")],
                        ]),
                    )
            except Exception:
                log.exception("send client log to %s", admin_id)
    except Exception:
        log.exception("dispatch client log")

    await reply_or_edit(
        update,
        f"<b>{rid}</b> ✅\n\nЛог отправлен админу. Жди ответа.",
        kb([[btn("← назад", f"r:{rid}")]]),
    )


async def cb_clog_read(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Админ помечает лог прочитанным."""
    q = update.callback_query
    _, _, log_s = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    try:
        log_id = int(log_s)
    except ValueError:
        await q.answer("bad id", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    db.mark_client_log_read(log_id)
    await q.answer("Помечено прочитанным")


async def cb_client_logs_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Админ: меню 📥 Логи от клиентов."""
    q = update.callback_query
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    parts = q.data.split(":")
    # clog:list[:page] или clog:list:unread[:page]
    page = 0
    unread_only = False
    if len(parts) >= 3 and parts[2] == "unread":
        unread_only = True
        if len(parts) >= 4:
            try:
                page = int(parts[3])
            except ValueError:
                page = 0
    elif len(parts) >= 3:
        try:
            page = int(parts[2])
        except ValueError:
            page = 0
    db: DB = ctx.application.bot_data["db"]
    PAGE = 10
    logs = db.client_logs_list(offset=page * PAGE, limit=PAGE, unread_only=unread_only)
    unread = db.client_logs_unread_count()
    filter_label = "🆕 Только непрочитанные" if not unread_only else "📋 Все логи"
    filter_cb = ("clog:list:unread:0") if not unread_only else ("clog:list:0")
    lines = [
        f"📥 <b>Логи от клиентов</b>",
        f"Непрочитанных: <b>{unread}</b>",
        "",
    ]
    if not logs:
        lines.append("<i>(пусто)</i>")
    rows: list = []
    for row in logs:
        try:
            lid = row["id"]
            uname = row["username"] or str(row["tg_id"])
            rid = row["router_id"]
            ts = row["created_at"]
            unread_flag = not row["read_by_admin"]
        except (IndexError, KeyError):
            continue
        tag = "🆕 " if unread_flag else ""
        btn_label = f"{tag}{rid} · @{uname[:15]} · {ts[:16]}"
        rows.append([btn(btn_label, f"clog:view:{lid}")])
    rows.append([btn(filter_label, filter_cb)])
    rows.append([btn("← назад", "cfg:menu")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_client_log_view(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, lid_s = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    try:
        lid = int(lid_s)
    except ValueError:
        await q.answer("bad id", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    row = db.get_client_log(lid)
    if row is None:
        await reply_or_edit(update, "Лог не найден (удалён?).",
                            kb([[btn("← к списку", "clog:list:0")]]))
        return
    try:
        rid = row["router_id"]
        uname = row["username"] or ""
        tgid = row["tg_id"]
        created = row["created_at"]
        lpath = row["log_path"] or ""
        preview = row["preview"] or ""
    except (IndexError, KeyError):
        await reply_or_edit(update, "Лог повреждён.",
                            kb([[btn("← к списку", "clog:list:0")]]))
        return
    db.mark_client_log_read(lid)
    text = (
        f"🆘 <b>Лог #{lid}</b>\n"
        f"Роутер: <b>{rid}</b>\n"
        f"Клиент: @{esc(uname or tgid)} (<code>{tgid}</code>)\n"
        f"Дата: {esc(created)}\n\n"
        f"Превью:\n<pre>{esc(preview)[:700]}</pre>"
    )
    rows: list = []
    if lpath and Path(lpath).exists():
        rows.append([btn("📎 Скачать файл", f"clog:file:{lid}")])
    rows.append([btn("📜 Аудит роутера", f"aud:r:{rid}:0")])
    rows.append([btn("← к списку", "clog:list:0")])
    await reply_or_edit(update, text, kb(rows))


async def cb_client_log_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, _, lid_s = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    try:
        lid = int(lid_s)
    except ValueError:
        await q.answer("bad id", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    row = db.get_client_log(lid)
    if row is None:
        await q.answer("лог не найден", show_alert=True)
        return
    try:
        lpath = row["log_path"]
        rid = row["router_id"]
    except (IndexError, KeyError):
        await q.answer("повреждён", show_alert=True)
        return
    p = Path(lpath)
    if not p.exists():
        await q.message.reply_text("Файл уже удалён (>30 дней?).")
        return
    await q.answer()
    with open(p, "rb") as fh:
        await q.message.reply_document(
            document=InputFile(fh, filename=p.name),
            caption=f"{rid} / лог #{lid}",
        )


# =============================================================================
# Stage 3 / A6: push-уведомления админу
# =============================================================================

def _admin_chat_ids(ctx: ContextTypes.DEFAULT_TYPE) -> list[int]:
    cfg: dict = ctx.application.bot_data["cfg"]
    explicit = cfg.get("admin_chat_ids") or []
    if explicit:
        return [int(x) for x in explicit]
    return [int(x) for x in (cfg.get("admins") or [])]


async def _push_admins(ctx: ContextTypes.DEFAULT_TYPE, text: str,
                       reply_markup=None) -> None:
    """Разослать админам сообщение. Все ошибки проглотить (логируем)."""
    log = ctx.application.bot_data.get("log")
    for admin_id in _admin_chat_ids(ctx):
        try:
            await ctx.bot.send_message(
                admin_id, text,
                parse_mode=ParseMode.HTML,
                reply_markup=reply_markup,
            )
        except Exception:
            if log:
                log.exception("push admin %s", admin_id)


# =============================================================================
# Stage 3 / A7: audit-лог UI (по роутеру)
# =============================================================================

AUDIT_PAGE = 15


async def cb_audit_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """aud:r:<rid>:<page>"""
    q = update.callback_query
    parts = q.data.split(":")
    if len(parts) != 4:
        await q.answer("bad callback", show_alert=True)
        return
    _, _, rid, page_s = parts
    try:
        page = int(page_s)
    except ValueError:
        page = 0
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    total = db.audit_count_by_router(rid)
    rows_data = db.audit_by_router(rid, offset=page * AUDIT_PAGE, limit=AUDIT_PAGE)
    total_pages = max(1, (total + AUDIT_PAGE - 1) // AUDIT_PAGE)
    lines = [
        f"📜 <b>Аудит {rid}</b>",
        f"Всего записей: <b>{total}</b>",
        f"Стр. {page + 1}/{total_pages}",
        "",
    ]
    if not rows_data:
        lines.append("<i>(нет записей)</i>")
    for a in rows_data:
        try:
            at = a["at"] or ""
            actor = a["username"] or (str(a["tg_id"]) if a["tg_id"] else "system")
            act = a["action"] or ""
            res = a["result"] or ""
            args = a["args"] or ""
        except (IndexError, KeyError):
            continue
        res_short = "✅" if res.startswith("ok") else "❌" if res.startswith("fail") else "·"
        line = f"<code>{esc(at[:16])}</code> · @{esc(actor)} · {esc(act)} {res_short}"
        if args and len(args) < 80:
            line += f"\n   <i>{esc(args)}</i>"
        lines.append(line)
    pager: list = []
    if page > 0:
        pager.append(btn("‹", f"aud:r:{rid}:{page - 1}"))
    pager.append(btn(f"{page + 1}/{total_pages}", "noop"))
    if page + 1 < total_pages:
        pager.append(btn("›", f"aud:r:{rid}:{page + 1}"))
    rows: list = []
    if pager:
        rows.append(pager)
    rows.append([btn("📥 Экспорт CSV", f"aud:csv:{rid}")])
    rows.append([btn("← к роутеру", f"r:{rid}")])
    await reply_or_edit(update, "\n".join(lines), kb(rows))


async def cb_audit_csv(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Выгрузить весь аудит роутера в CSV-файл."""
    q = update.callback_query
    _, _, rid = q.data.split(":")
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await q.answer("Только админ", show_alert=True)
        return
    db: DB = ctx.application.bot_data["db"]
    rows = db.audit_all_by_router(rid)
    import csv as _csv
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["at", "tg_id", "username", "action", "args", "result"])
    for a in rows:
        try:
            w.writerow([
                a["at"], a["tg_id"], a["username"] or "",
                a["action"], a["args"] or "", a["result"] or "",
            ])
        except (IndexError, KeyError):
            continue
    data = buf.getvalue().encode("utf-8")
    await q.answer("Готовлю CSV…")
    await q.message.reply_document(
        document=InputFile(io.BytesIO(data), filename=f"audit_{rid}.csv"),
        caption=f"📜 Аудит {rid} — {len(rows)} записей",
    )


# =============================================================================
# Stage 3 / A8: Глобальный тест — новый формат
# =============================================================================
# Запускаемый только online роутеры, параллелизм 5, на каждый 30 сек.
# Результат — файл .log с блоками на роутер + summary.

GLOBAL_TEST_MAX_WORKERS = 5
GLOBAL_TEST_ROUTER_TIMEOUT = 30


async def cb_global_test(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Глобальный тест v2 — только админ."""
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        await reply_or_edit(update, "Только админ.",
                            kb([[btn("← Главная", "menu:main")]]))
        return
    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    routers = discover(rcfg)
    # Только online, не lifecycle-изменённые.
    states = {s["router_id"]: s for s in db.all_states()}

    def _is_target(r: Router) -> bool:
        st = states.get(r.id)
        if st is None:
            return False
        try:
            lc = st["lifecycle_status"]
        except (IndexError, KeyError):
            lc = None
        if lc in ("transit", "maintenance"):
            return False
        try:
            return bool(st["online"])
        except (IndexError, KeyError):
            return False

    targets = [r for r in routers if _is_target(r)]
    if not targets:
        await reply_or_edit(update, "Нет online-роутеров для теста.",
                            kb([[btn("← назад", "menu:main")]]))
        return

    await reply_or_edit(
        update,
        f"🧪 Глобальный тест — запускаю на {len(targets)} роутерах "
        f"(параллельно до {GLOBAL_TEST_MAX_WORKERS}, таймаут "
        f"{GLOBAL_TEST_ROUTER_TIMEOUT}s каждому)…",
    )

    loop = asyncio.get_event_loop()

    def _run(r: Router):
        try:
            return do_router_selftest(r, rcfg["ssh"])
        except Exception as e:
            return ("FAIL", [f"[FAIL] exception: {e}"], str(e))

    sem = asyncio.Semaphore(GLOBAL_TEST_MAX_WORKERS)

    async def _task(r: Router):
        async with sem:
            try:
                return r, await asyncio.wait_for(
                    loop.run_in_executor(None, _run, r),
                    timeout=GLOBAL_TEST_ROUTER_TIMEOUT + 5,
                )
            except asyncio.TimeoutError:
                return r, ("FAIL", ["[FAIL] timeout"], "timeout")
            except Exception as e:
                return r, ("FAIL", [f"[FAIL] exception: {e}"], str(e))

    results = await asyncio.gather(*[_task(r) for r in targets])

    # Собираем файл
    ts = dt.datetime.utcnow().strftime("%Y-%m-%d_%H-%M")
    out_lines: list[str] = []
    pass_n = warn_n = fail_n = 0
    overrides = rcfg.get("overrides") or {}
    for r, (verdict, lines, raw) in results:
        st = states.get(r.id)
        owner = ""
        try:
            label = st["label"] or ""
        except (IndexError, KeyError):
            label = ""
        label = label or overrides.get(r.id, "")
        country_iso = ""
        try:
            country_iso = st["egress_country_iso"] or ""
        except (IndexError, KeyError):
            pass
        header_extras = []
        if label:
            header_extras.append(f"label: {label}")
        if country_iso:
            header_extras.append(country_iso)
        extras = "  ·  ".join(header_extras)
        out_lines.append("=" * 60)
        out_lines.append(f"{r.id}" + (f"  ·  {extras}" if extras else ""))
        out_lines.append("=" * 60)
        out_lines.extend(lines)
        out_lines.append(f"RESULT: {'✅ PASS' if verdict == 'PASS' else '⚠ WARN' if verdict == 'WARN' else '❌ FAIL'}")
        out_lines.append("")
        if verdict == "PASS":
            pass_n += 1
        elif verdict == "WARN":
            warn_n += 1
        else:
            fail_n += 1
    out_lines.append("=" * 60)
    out_lines.append(f"SUMMARY  ({ts})")
    out_lines.append("=" * 60)
    out_lines.append(f"Total tested: {len(targets)}")
    out_lines.append(f"✅ PASS: {pass_n}")
    out_lines.append(f"⚠ WARN: {warn_n}")
    out_lines.append(f"❌ FAIL: {fail_n}")
    body = "\n".join(out_lines) + "\n"
    runs_dir = Path(cfg["paths"]["runs"]) / "global"
    runs_dir.mkdir(parents=True, exist_ok=True)
    fpath = runs_dir / f"global_test_{ts}.log"
    fpath.write_text(body, encoding="utf-8")
    db.audit(u.id, u.username, None, "global_test",
             f"total={len(targets)} pass={pass_n} warn={warn_n} fail={fail_n}",
             "ok")
    log.info("global test done: pass=%d warn=%d fail=%d", pass_n, warn_n, fail_n)

    summary = (
        f"🧪 <b>Глобальный тест завершён</b>\n"
        f"Протестировано: {len(targets)}/{len(targets)} online-роутеров\n"
        f"✅ {pass_n}  ⚠ {warn_n}  ❌ {fail_n}"
    )
    q = update.callback_query
    chat = update.effective_chat
    chat_id = chat.id if chat else (q.message.chat_id if q else None)
    if chat_id is None:
        return
    with open(fpath, "rb") as fh:
        await ctx.bot.send_document(
            chat_id,
            document=InputFile(fh, filename=fpath.name),
            caption=summary,
            parse_mode=ParseMode.HTML,
            reply_markup=kb([[btn("← Главная", "menu:main")]]),
        )


# =============================================================================
# Admin: VLESS пул
# =============================================================================

async def cb_pool_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    db: DB = ctx.application.bot_data["db"]
    pool = db.all_vless()
    if not pool:
        text = "🔗 <b>VLESS-пул пуст</b>\n\nДобавь ссылки чтобы клиенты могли их выбирать."
    else:
        lines = [f"🔗 <b>VLESS-пул</b> ({len(pool)} ссылок):\n"]
        for v in pool[:40]:
            lines.append(f"• <b>{esc(v['remark'])}</b> — <code>{esc(v['host'])}</code>")
        text = "\n".join(lines)
    rows = [
        [btn("➕ Добавить", "pool:add"), btn("🗑 Удалить", "pool:del:0")],
        [btn("🔧 Привязки", "pool:bind:0")],
        [btn("← Главная", "menu:main")],
    ]
    await reply_or_edit(update, text, kb(rows))


async def cb_pool_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    ctx.user_data["state"] = "awaiting_vless_urls"
    await reply_or_edit(
        update,
        "Пришли одну или несколько строк vless://... (каждая с новой строки).\n\n"
        "Бот распарсит <code>remark</code> (после #) и хост, и сохранит в пул.\n\n"
        "Или /cancel чтобы отменить.",
        kb([[btn("← Отмена", "pool:list")]]),
    )


async def cb_pool_del_page(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, page_s = q.data.split(":")
    page = int(page_s)
    db: DB = ctx.application.bot_data["db"]
    pool = db.all_vless()
    start = page * VLESS_PAGE
    chunk = pool[start : start + VLESS_PAGE]
    rows = []
    for v in chunk:
        rows.append(
            [btn(f"🗑 {v['remark']} ({v['host']})"[:60], f"pool:del_one:{v['id']}")]
        )
    nav = []
    if page > 0:
        nav.append(btn("←", f"pool:del:{page-1}"))
    if start + VLESS_PAGE < len(pool):
        nav.append(btn("→", f"pool:del:{page+1}"))
    if nav:
        rows.append(nav)
    rows.append([btn("← в пул", "pool:list")])
    await reply_or_edit(update, "Выбери ссылку для удаления:", kb(rows))


async def cb_pool_del_one(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, vid_s = q.data.split(":")
    vid = int(vid_s)
    db: DB = ctx.application.bot_data["db"]
    v = db.vless_by_id(vid)
    if v:
        db.delete_vless(vid)
        db.audit(u.id, u.username, None, "vless_pool_del", f"id={vid} {v['remark']}", "ok")
    await cb_pool_del_page_manual(update, ctx, 0)


async def cb_pool_del_page_manual(update: Update, ctx: ContextTypes.DEFAULT_TYPE, page: int):
    db: DB = ctx.application.bot_data["db"]
    pool = db.all_vless()
    if not pool:
        await reply_or_edit(update, "Пул пуст.", kb([[btn("← в пул", "pool:list")]]))
        return
    chunk = pool[page * VLESS_PAGE : (page + 1) * VLESS_PAGE]
    rows = [[btn(f"🗑 {v['remark']} ({v['host']})"[:60], f"pool:del_one:{v['id']}")] for v in chunk]
    rows.append([btn("← в пул", "pool:list")])
    await reply_or_edit(update, "Выбери ссылку для удаления:", kb(rows))


async def cb_pool_bind(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Экран выбора роутера → потом ссылок-чекбоксов."""
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, page_s = q.data.split(":")
    page = int(page_s)
    ids = all_router_ids(ctx)
    chunk = ids[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
    rows = [[btn(rid, f"pool:bind_r:{rid}:0")] for rid in chunk]
    nav = []
    if page > 0:
        nav.append(btn("←", f"pool:bind:{page-1}"))
    if (page + 1) * PAGE_SIZE < len(ids):
        nav.append(btn("→", f"pool:bind:{page+1}"))
    if nav:
        rows.append(nav)
    rows.append([btn("← в пул", "pool:list")])
    await reply_or_edit(update, "Выбери роутер:", kb(rows))


async def cb_pool_bind_r(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid, page_s = q.data.split(":")
    page = int(page_s)
    db: DB = ctx.application.bot_data["db"]
    pool = db.all_vless()
    if not pool:
        await reply_or_edit(
            update,
            "Пул пуст — нечего привязывать. Сначала добавь ссылки.",
            kb([[btn("← назад", "pool:list")]]),
        )
        return
    allowed_ids = {r["vless_id"] for r in db.q("SELECT vless_id FROM router_vless_allow WHERE router_id=?", (rid,))}
    has_restrictions = bool(allowed_ids)
    chunk = pool[page * VLESS_PAGE : (page + 1) * VLESS_PAGE]
    rows = []
    for v in chunk:
        checked = "✅" if v["id"] in allowed_ids or not has_restrictions else "☐"
        rows.append([btn(f"{checked} {v['remark']} ({v['host']})"[:60], f"pool:bind_t:{rid}:{v['id']}:{page}")])
    nav = []
    if page > 0:
        nav.append(btn("←", f"pool:bind_r:{rid}:{page-1}"))
    if (page + 1) * VLESS_PAGE < len(pool):
        nav.append(btn("→", f"pool:bind_r:{rid}:{page+1}"))
    if nav:
        rows.append(nav)
    rows.append(
        [
            btn("🧹 Разрешить всё", f"pool:bind_clr:{rid}"),
            btn("← в пул", "pool:list"),
        ]
    )
    subt = "(пусто = доступен ВЕСЬ пул)" if not has_restrictions else "(ограничен список ниже)"
    await reply_or_edit(
        update,
        f"<b>{rid}</b> — привязки ссылок {subt}\n\nНажми чтобы вкл/выкл:",
        kb(rows),
    )


async def cb_pool_bind_toggle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid, vid_s, page_s = q.data.split(":")
    vid = int(vid_s)
    page = int(page_s)
    db: DB = ctx.application.bot_data["db"]
    existing = db.q("SELECT vless_id FROM router_vless_allow WHERE router_id=?", (rid,))
    ids = {r["vless_id"] for r in existing}
    if not ids:
        # значит сейчас разрешено всё; включаем ограничение и оставляем все кроме этой
        all_ids = [v["id"] for v in db.all_vless()]
        ids = set(all_ids) - {vid}
    else:
        if vid in ids:
            ids.discard(vid)
        else:
            ids.add(vid)
    db.set_router_allow(rid, sorted(ids))
    db.audit(u.id, u.username, rid, "pool_bind_toggle", f"vid={vid}", "ok")
    # перерисовать
    q.data = f"pool:bind_r:{rid}:{page}"
    await cb_pool_bind_r(update, ctx)


async def cb_pool_bind_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid = q.data.split(":")
    db: DB = ctx.application.bot_data["db"]
    db.ex("DELETE FROM router_vless_allow WHERE router_id=?", (rid,))
    db.audit(u.id, u.username, rid, "pool_bind_clear", None, "ok")
    q.data = f"pool:bind_r:{rid}:0"
    await cb_pool_bind_r(update, ctx)


# =============================================================================
# Admin: клиенты / заявки / invite-коды
# =============================================================================

async def cb_clients_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    db: DB = ctx.application.bot_data["db"]
    clients = db.all_clients()
    lines = ["👥 <b>Клиенты</b>\n"]
    for c in clients:
        rids = db.client_routers(c["tg_id"])
        uname = f"@{c['username']}" if c["username"] else c["first_name"] or str(c["tg_id"])
        tag = "👑" if c["role"] == "admin" else "👤"
        lines.append(f"{tag} {esc(uname)} <code>{c['tg_id']}</code> → {', '.join(rids) or '—'}")
    text = "\n".join(lines) if clients else "Пока никого нет."
    rows = [
        [btn("📮 Заявки", "req:list"), btn("🎟 Коды", "inv:list")],
        [btn("← Главная", "menu:main")],
    ]
    await reply_or_edit(update, text, kb(rows))


async def cb_requests_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    db: DB = ctx.application.bot_data["db"]
    pending = db.pending_requests()
    if not pending:
        await reply_or_edit(update, "Заявок нет.", kb([[btn("← Главная", "menu:main")]]))
        return
    rows = []
    for r in pending:
        uname = f"@{r['username']}" if r["username"] else str(r["tg_id"])
        rows.append([btn(f"{uname} → {r['router_id']}"[:60], f"req:view:{r['id']}")])
    rows.append([btn("← Главная", "menu:main")])
    await reply_or_edit(update, f"📮 <b>Заявки</b> ({len(pending)}):", kb(rows))


async def cb_request_view(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid_s = q.data.split(":")
    rid = int(rid_s)
    db: DB = ctx.application.bot_data["db"]
    req = db.get_request(rid)
    if not req:
        await reply_or_edit(update, "Заявка не найдена.", kb([[btn("← к списку", "req:list")]]))
        return
    text = (
        f"📮 Заявка #{req['id']}\n"
        f"Кто: @{esc(req['username'] or '—')}  <code>{req['tg_id']}</code>\n"
        f"Роутер: <b>{req['router_id']}</b>\n"
        f"Сообщение: {esc(req['message'] or '—')}\n"
        f"Создана: {req['created_at']}"
    )
    rows = [
        [btn("✅ Одобрить", f"req:ok:{req['id']}"), btn("❌ Отклонить", f"req:no:{req['id']}")],
        [btn("← к списку", "req:list")],
    ]
    await reply_or_edit(update, text, kb(rows))


async def cb_request_decide(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, action, rid_s = q.data.split(":")
    rid = int(rid_s)
    db: DB = ctx.application.bot_data["db"]
    log = ctx.application.bot_data["log"]
    req = db.get_request(rid)
    if not req:
        await q.answer("не найдена", show_alert=True)
        return
    if action == "ok":
        db.upsert_client(req["tg_id"], req["username"], None, role="client")
        db.bind(req["tg_id"], req["router_id"])
        db.decide_request(rid, "approved", u.id)
        db.audit(u.id, u.username, req["router_id"], "req_approve", f"tg={req['tg_id']}", "ok")
        # Уведомить клиента
        try:
            await ctx.bot.send_message(
                req["tg_id"],
                f"✅ Администратор одобрил твою заявку на <b>{req['router_id']}</b>.\nОтправь /start чтобы начать.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            log.warning("не смог уведомить %s", req["tg_id"])
    else:
        db.decide_request(rid, "rejected", u.id)
        db.audit(u.id, u.username, req["router_id"], "req_reject", f"tg={req['tg_id']}", "ok")
        try:
            await ctx.bot.send_message(
                req["tg_id"],
                f"❌ Заявка на {req['router_id']} отклонена.",
            )
        except Exception:
            pass
    await cb_requests_list(update, ctx)


async def cb_invites_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    db: DB = ctx.application.bot_data["db"]
    codes = db.active_invites()
    if not codes:
        text = "🎟 Активных кодов нет."
    else:
        lines = ["🎟 <b>Активные коды</b>:\n"]
        for c in codes:
            lines.append(f"<code>{c['code']}</code> → {c['router_id']} (до {c['expires_at']} UTC)")
        text = "\n".join(lines)
    rows = [
        [btn("➕ Сгенерировать", "inv:new:0")],
        [btn("← Главная", "menu:main")],
    ]
    await reply_or_edit(update, text, kb(rows))


async def cb_invite_new_pick_router(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, page_s = q.data.split(":")
    page = int(page_s)
    ids = all_router_ids(ctx)
    chunk = ids[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
    rows = [[btn(rid, f"inv:gen:{rid}")] for rid in chunk]
    nav = []
    if page > 0:
        nav.append(btn("←", f"inv:new:{page-1}"))
    if (page + 1) * PAGE_SIZE < len(ids):
        nav.append(btn("→", f"inv:new:{page+1}"))
    if nav:
        rows.append(nav)
    rows.append([btn("← к кодам", "inv:list")])
    await reply_or_edit(update, "Для какого роутера сгенерировать код?", kb(rows))


async def cb_invite_generate(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid = q.data.split(":")
    db: DB = ctx.application.bot_data["db"]
    code = db.create_invite(rid, u.id, ttl_hours=24)
    db.audit(u.id, u.username, rid, "invite_new", code, "ok")
    text = (
        f"🎟 Код создан:\n\n"
        f"<code>{code}</code>\n\n"
        f"Для роутера: <b>{rid}</b>\n"
        f"Действителен 24 часа, одноразовый.\n\n"
        "Отправь код клиенту. Он должен написать боту и нажать «У меня есть код»."
    )
    await reply_or_edit(update, text, kb([[btn("← к кодам", "inv:list")]]))


# =============================================================================
# Ярлыки: переименовать / удалить (admin)
# =============================================================================

async def cb_label_rename(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid = q.data.split(":")
    ctx.user_data["state"] = "awaiting_label"
    ctx.user_data["state_rid"] = rid
    await reply_or_edit(
        update,
        f"Пришли новое имя для <b>{rid}</b> текстом.\n"
        "Например: «Вася Петров» или «Дача на Даче».\n\n"
        "Или /cancel чтобы отменить.",
        kb([[btn("← Отмена", f"r:{rid}")]]),
    )


async def cb_label_delete(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid = q.data.split(":")
    text = (
        f"<b>{rid}</b> — убрать из мониторинга?\n\n"
        "Это удалит ярлык из config.yaml, state и разрешения VLESS.\n"
        "Сами привязки клиентов и audit сохранятся.\n\n"
        "Если роутер позже снова подключится — вернётся с пустым именем."
    )
    await reply_or_edit(
        update,
        text,
        kb_confirm(f"label:delgo:{rid}", f"r:{rid}"),
    )


async def cb_label_delete_go(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, _, rid = q.data.split(":")
    cfg: dict = ctx.application.bot_data["cfg"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    db: DB = ctx.application.bot_data["db"]
    log = ctx.application.bot_data["log"]
    path = cfg["paths"]["r_config"]
    try:
        ok = cfg_edit_label(path, "remove", rid)
    except Exception as e:
        log.exception("cfg_edit_label remove")
        await reply_or_edit(update, f"❌ Ошибка: {esc(e)}", kb([[btn("← назад", f"r:{rid}")]]))
        return
    # перезагрузить r_config
    from importlib import reload
    ctx.application.bot_data["r_config"] = load_r_config(cfg)
    db.delete_router_state(rid)
    db.audit(u.id, u.username, rid, "label_delete", None, "ok" if ok else "not_found")
    text = f"✅ {rid} удалён из мониторинга." if ok else f"{rid} не был в конфиге."
    await reply_or_edit(update, text, kb([[btn("← Главная", "menu:main")]]))


# =============================================================================
# Mass операции (admin)
# =============================================================================

async def cb_mass_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    rows = [
        [btn("🔧 Pall — restart podkop ВСЕМ online", "mass:pall")],
        [btn("🟡 Pfail — только где STOP", "mass:pfail")],
        [btn("🔁 Rall — reboot ВСЕМ online", "mass:rall")],
        [btn("← Главная", "menu:main")],
    ]
    await reply_or_edit(
        update,
        "🔔 <b>Массовые операции</b>\n\nТребуют ввода <code>YES</code> текстом после подтверждения.",
        kb(rows),
    )


async def cb_mass_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    q = update.callback_query
    _, op = q.data.split(":")
    human = {
        "pall": "перезапустить podkop на ВСЕХ онлайн роутерах",
        "pfail": "перезапустить podkop ТОЛЬКО где STOP",
        "rall": "ПЕРЕЗАГРУЗИТЬ (reboot) все онлайн роутеры",
    }.get(op, op)
    ctx.user_data["state"] = f"awaiting_yes_{op}"
    await reply_or_edit(
        update,
        f"Ты точно хочешь {human}?\n\n"
        "Пришли текстом <b>YES</b> (заглавными) чтобы подтвердить. Любой другой ответ — отмена.",
        kb([[btn("← Отмена", "mass:menu")]]),
    )


async def _run_mass(update: Update, ctx: ContextTypes.DEFAULT_TYPE, op: str):
    u = update.effective_user
    if not u:
        return
    db: DB = ctx.application.bot_data["db"]
    rcfg: dict = ctx.application.bot_data["r_config"]
    log = ctx.application.bot_data["log"]

    routers = current_routers(ctx)
    states = {s["router_id"]: s for s in db.all_states()}

    targets: list[Router] = []
    for r in routers:
        s = states.get(r.id)
        if op == "pall":
            targets.append(r)
        elif op == "pfail":
            if s and s["podkop_status"] == "STOP":
                targets.append(r)
        elif op == "rall":
            targets.append(r)

    if not targets:
        await update.message.reply_text("Нет подходящих целей.")
        return

    await update.message.reply_text(
        f"Запускаю {op} на {len(targets)} роутерах, жди."
    )

    ssh_cfg = rcfg["ssh"]
    loop = asyncio.get_event_loop()

    def _exec(r: Router) -> tuple[str, bool, str]:
        if op == "rall":
            ok, msg = do_reboot(r, ssh_cfg)
        else:
            ok, msg = do_podkop_restart(r, ssh_cfg)
        return r.id, ok, msg

    results = await loop.run_in_executor(
        None,
        lambda: [
            _exec(r) for r in targets   # последовательно, чтобы не нагрузить
        ],
    )

    ok_n = sum(1 for _, ok, _ in results if ok)
    fail_n = len(results) - ok_n
    for rid, ok, _ in results:
        db.audit(u.id, u.username, rid, f"mass_{op}", None, "ok" if ok else "fail")

    fails_txt = "\n".join(
        f"• {rid}: {msg[:100]}" for rid, ok, msg in results if not ok
    )
    text = (
        f"<b>Mass {op} завершён</b>\n\n"
        f"✅ успех: {ok_n}  ·  ❌ ошибок: {fail_n}"
    )
    if fails_txt:
        text += f"\n\n<pre>{esc(fails_txt[:1500])}</pre>"
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    log.info("mass %s by %s: %d ok / %d fail", op, u.id, ok_n, fail_n)


# =============================================================================
# Настройки (admin): обновления, бэкапы, audit-журнал
# =============================================================================

async def cb_cfg_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    cfg: dict = ctx.application.bot_data["cfg"]
    dig = cfg["digest"]
    db: DB = ctx.application.bot_data["db"]
    try:
        unread_logs = db.client_logs_unread_count()
    except Exception:
        unread_logs = 0
    clog_label = f"📥 Логи от клиентов ({unread_logs})" if unread_logs else "📥 Логи от клиентов"
    rows = [
        [btn("📜 Журнал (audit)", "cfg:audit:0")],
        [btn(clog_label, "clog:list:0")],
        [btn("💾 Бэкап сейчас", "cfg:backup")],
        [btn("🔄 Обновить из Git", "cfg:update")],
        [btn("📊 Тест digest", "cfg:digest_test")],
        [btn("← Главная", "menu:main")],
    ]
    text = (
        f"⚙️ <b>Настройки</b>\n\n"
        f"Digest: {'вкл' if dig['enabled'] else 'выкл'} · {dig['time']} {dig['timezone']}\n"
        f"Poll: {cfg['poll']['interval_minutes']} мин\n"
        f"Auto-update: {'вкл' if cfg['auto_update']['enabled'] else 'выкл'}\n"
        f"Версия: v{VERSION}"
    )
    await reply_or_edit(update, text, kb(rows))


async def cb_cfg_audit(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    db: DB = ctx.application.bot_data["db"]
    rows_db = db.audit_recent(30)
    lines = ["📜 <b>Последние 30 действий</b>\n"]
    for r in rows_db:
        who = f"@{r['username']}" if r["username"] else str(r["tg_id"] or "—")
        lines.append(
            f"<code>{r['at']}</code> {who} {r['router_id'] or '—'} "
            f"<b>{r['action']}</b> → {r['result'] or ''}"[:180]
        )
    await reply_or_edit(
        update,
        "\n".join(lines)[:3900],
        kb([[btn("← назад", "cfg:menu")]]),
    )


async def cb_cfg_backup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    cfg: dict = ctx.application.bot_data["cfg"]
    log = ctx.application.bot_data["log"]
    await update.callback_query.answer("Готовлю бэкап...")
    try:
        archive = _make_backup(cfg)
    except Exception as e:
        log.exception("backup")
        await update.callback_query.message.reply_text(f"❌ Ошибка бэкапа: {esc(e)}")
        return
    with open(archive, "rb") as f:
        await update.callback_query.message.reply_document(
            document=InputFile(f, filename=archive.name),
            caption=f"Бэкап r-bot от {dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        )


async def cb_cfg_update(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    cfg: dict = ctx.application.bot_data["cfg"]
    log = ctx.application.bot_data["log"]
    repo_dir = cfg["auto_update"]["repo_dir"]
    await update.callback_query.answer("git pull...")
    try:
        proc = subprocess.run(
            ["git", "-C", repo_dir, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            await update.callback_query.message.reply_text(
                f"❌ git pull rc={proc.returncode}\n<pre>{esc(out[:1500])}</pre>",
                parse_mode=ParseMode.HTML,
            )
            return
        await update.callback_query.message.reply_text(
            f"<pre>{esc(out[:1500])}</pre>\n\nТеперь выполни на сервере: <code>sudo bash {repo_dir}/scripts/update.sh</code>",
            parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        log.exception("git pull")
        await update.callback_query.message.reply_text(f"❌ {esc(e)}")


async def cb_cfg_digest_test(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(ctx, u.id):
        return
    await update.callback_query.answer("Готовлю тестовый отчёт...")
    text = _build_digest(ctx)
    await update.callback_query.message.reply_text(text, parse_mode=ParseMode.HTML)


# =============================================================================
# Гость: ввод кода / заявка
# =============================================================================

async def cb_guest_code(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["state"] = "awaiting_code"
    await reply_or_edit(
        update,
        "Пришли код приглашения текстом (вида <code>id07-XK9P</code>).\n\n/cancel чтобы отменить.",
    )


async def cb_guest_request(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["state"] = "awaiting_request"
    await reply_or_edit(
        update,
        "Пришли одной строкой: <code>idNN что-нибудь</code>.\n"
        "Например: <code>id07 Вася, меня прислал Ярослав</code>.\n\n"
        "/cancel чтобы отменить.",
    )


# =============================================================================
# Текстовый ввод (FSM через ctx.user_data['state'])
# =============================================================================

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    msg = update.effective_message
    if not u or not msg or not msg.text:
        return
    state = ctx.user_data.get("state")
    text = msg.text.strip()

    if text == "/cancel":
        ctx.user_data.clear()
        await msg.reply_text("Отменено.")
        await cmd_start(update, ctx)
        return

    db: DB = ctx.application.bot_data["db"]
    cfg: dict = ctx.application.bot_data["cfg"]
    log = ctx.application.bot_data["log"]

    # --- YES для mass ---
    if state and state.startswith("awaiting_yes_"):
        if not is_admin(ctx, u.id):
            return
        op = state[len("awaiting_yes_") :]
        ctx.user_data.pop("state", None)
        if text != "YES":
            await msg.reply_text("Отмена.")
            return
        await _run_mass(update, ctx, op)
        return

    # --- invite code ---
    if state == "awaiting_code":
        ctx.user_data.pop("state", None)
        code = text.strip().upper()
        rid = db.use_invite(code, u.id)
        if not rid:
            await msg.reply_text("Код не подошёл (неверный, истёк или уже использован).")
            return
        db.upsert_client(u.id, u.username, u.first_name, role="client")
        db.bind(u.id, rid)
        db.audit(u.id, u.username, rid, "invite_use", code, "ok")
        await msg.reply_text(f"✅ Ты привязан к <b>{rid}</b>.", parse_mode=ParseMode.HTML)
        await cmd_start(update, ctx)
        return

    # --- request ---
    if state == "awaiting_request":
        ctx.user_data.pop("state", None)
        m = re.match(r"^(id\d{1,2})\s+(.+)$", text, re.IGNORECASE)
        if not m:
            await msg.reply_text("Формат: `idNN текст сообщения`", parse_mode=ParseMode.MARKDOWN)
            return
        rid = m.group(1).lower()
        if len(rid) == 4 and rid[2].isdigit() and rid[3].isdigit():
            pass
        else:
            # Нормализовать к формату idNN
            n = int(rid[2:])
            rid = f"id{n:02d}"
        message = m.group(2)
        req_id = db.create_request(u.id, u.username, rid, message)
        db.audit(u.id, u.username, rid, "req_new", f"req={req_id}", "ok")
        # Уведомить всех admin
        for admin_id in cfg["admins"]:
            try:
                await ctx.bot.send_message(
                    admin_id,
                    f"📮 Новая заявка #{req_id}:\n@{esc(u.username or '—')} → {rid}\n\n«{esc(message[:300])}»",
                    parse_mode=ParseMode.HTML,
                    reply_markup=kb([[btn("Открыть", f"req:view:{req_id}")]]),
                )
            except Exception:
                pass
        await msg.reply_text("Заявка отправлена администратору. Жди ответа.")
        return

    # --- VLESS URLs ---
    if state == "awaiting_vless_urls":
        if not is_admin(ctx, u.id):
            return
        ctx.user_data.pop("state", None)
        urls = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("vless://")]
        if not urls:
            await msg.reply_text("Не вижу строк vless://... Попробуй ещё раз.")
            return
        added, duplicates = 0, 0
        for url in urls:
            remark, host = parse_vless(url)
            vid = db.add_vless(url, remark, host, u.id)
            if vid:
                added += 1
            else:
                duplicates += 1
        db.audit(u.id, u.username, None, "pool_add", f"added={added}", "ok")
        await msg.reply_text(
            f"✅ Добавлено: {added}.\n" +
            (f"Уже были: {duplicates}" if duplicates else ""),
        )
        return

    # --- label (rename/add) ---
    if state == "awaiting_label":
        if not is_admin(ctx, u.id):
            return
        rid = ctx.user_data.get("state_rid")
        ctx.user_data.pop("state", None)
        ctx.user_data.pop("state_rid", None)
        if not rid:
            return
        path = cfg["paths"]["r_config"]
        try:
            cfg_edit_label(path, "rename", rid, text)
            ctx.application.bot_data["r_config"] = load_r_config(cfg)
            db.audit(u.id, u.username, rid, "label_rename", text, "ok")
            await msg.reply_text(f"✅ {rid}: «{esc(text)}»", parse_mode=ParseMode.HTML)
        except Exception as e:
            log.exception("label rename")
            await msg.reply_text(f"❌ {esc(e)}")
        return

    # --- Stage 2 / A2: custom VLESS (admin) ---
    if state == "awaiting_custom_vless":
        if not is_admin(ctx, u.id):
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return
        rid = ctx.user_data.get("state_rid")
        ctx.user_data.pop("state", None)
        ctx.user_data.pop("state_rid", None)
        if not rid:
            return
        ok, info, parsed = validate_custom_vless(text)
        if not ok:
            await msg.reply_text(
                f"❌ Невалидный VLESS: {esc(info)}\n\n"
                "Нужны: <code>vless://UUID@host:port?security=reality&pbk=...&sni=...</code>\n\n"
                "Попробуй ещё раз через «🔧 Custom VLESS» или /cancel.",
                parse_mode=ParseMode.HTML,
            )
            return
        ctx.user_data["pending_custom_vless_url"] = text.strip()
        ctx.user_data["pending_custom_vless_rid"] = rid
        masked = mask_vless_for_audit(text)
        warn = (
            f"<b>{rid}</b> — подтверди custom VLESS\n\n"
            f"Краткая форма: <code>{esc(info)}</code>\n"
            f"Маска для audit: <code>{esc(masked)}</code>\n\n"
            "⚠ После применения роутер выйдет из ротации пула.\n"
            "Чтобы вернуть — нажми «🔁 Вернуть в пул»."
        )
        await msg.reply_text(
            warn,
            parse_mode=ParseMode.HTML,
            reply_markup=kb([
                [btn("✅ Применить", f"vless:capply:{rid}")],
                [btn("✖ Отмена", f"r:{rid}")],
            ]),
        )
        return

    # --- Stage 2 / клиентский пункт 7: WiFi SSID ---
    if state == "awaiting_wifi_ssid":
        rid = ctx.user_data.get("state_rid")
        if not rid:
            ctx.user_data.pop("state", None)
            return
        # Проверяем доступ
        if not client_owns_router(ctx, u.id, rid):
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return
        ssid = text.strip()
        # SSID: 1..32 байта (utf-8). Контроль-символы запрещены.
        if not ssid or len(ssid.encode("utf-8")) > 32:
            await msg.reply_text(
                "❌ SSID должен быть 1–32 байта (UTF-8). Пришли ещё раз или /cancel."
            )
            return
        if any(ord(c) < 32 for c in ssid):
            await msg.reply_text(
                "❌ В SSID нельзя использовать управляющие символы. Пришли ещё раз или /cancel."
            )
            return
        ctx.user_data["pending_wifi_ssid"] = ssid
        ctx.user_data["state"] = "awaiting_wifi_pwd"
        await msg.reply_text(
            f"📶 <b>{rid}</b>\nSSID принят: <code>{esc(ssid)}</code>\n\n"
            "Шаг 2/2: пришли новый пароль (8–63 символа ASCII).\n\n"
            "/cancel чтобы отменить.",
            parse_mode=ParseMode.HTML,
            reply_markup=kb([[btn("✖ Отмена", f"wifi:menu:{rid}")]]),
        )
        return

    # --- Stage 2 / клиентский пункт 7: WiFi password ---
    if state == "awaiting_wifi_pwd":
        rid = ctx.user_data.get("state_rid")
        if not rid:
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("pending_wifi_ssid", None)
            return
        if not client_owns_router(ctx, u.id, rid):
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            ctx.user_data.pop("pending_wifi_ssid", None)
            return
        pwd = text.strip()
        # WPA2-PSK требует 8..63 печатных ASCII.
        if len(pwd) < 8 or len(pwd) > 63:
            await msg.reply_text(
                "❌ Пароль 8–63 символа. Пришли ещё раз или /cancel."
            )
            return
        try:
            pwd.encode("ascii")
        except UnicodeEncodeError:
            await msg.reply_text(
                "❌ Только ASCII (буквы/цифры/знаки). Пришли ещё раз или /cancel."
            )
            return
        if any(ord(c) < 32 or ord(c) == 127 for c in pwd):
            await msg.reply_text(
                "❌ Управляющие символы запрещены. Пришли ещё раз или /cancel."
            )
            return
        ssid = ctx.user_data.get("pending_wifi_ssid", "")
        ctx.user_data["pending_wifi_pwd"] = pwd
        ctx.user_data["pending_wifi_rid"] = rid
        ctx.user_data.pop("state", None)
        ctx.user_data.pop("state_rid", None)
        masked = "•" * min(len(pwd), 12)
        warn = (
            f"📶 <b>{rid}</b> — подтверди новые WiFi-настройки\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"SSID: <b>{esc(ssid)}</b>\n"
            f"Пароль: <code>{masked}</code> (длина {len(pwd)})\n\n"
            "⚠ После применения <b>все</b> устройства отключатся и должны "
            "переподключиться с новым паролем (включая телефон, с которого "
            "ты пишешь, если он на этом WiFi).\n\n"
            "Применить?"
        )
        await msg.reply_text(
            warn,
            parse_mode=ParseMode.HTML,
            reply_markup=kb([
                [btn("✅ Применить", f"wifi:wapply:{rid}")],
                [btn("✖ Отмена", f"wifi:menu:{rid}")],
            ]),
        )
        return

    # --- Stage 2 / A9: добавить владельца ---
    if state == "awaiting_owner_add":
        if not is_admin(ctx, u.id):
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return
        rid = ctx.user_data.get("state_rid")
        ctx.user_data.pop("state", None)
        ctx.user_data.pop("state_rid", None)
        if not rid:
            return
        # Принимаем @username или числовой tg_id.
        target = text.strip().lstrip("@")
        tg_id: int | None = None
        username: str | None = None
        if target.isdigit():
            tg_id = int(target)
            row = db.get_client(tg_id)
            if row:
                try:
                    username = row["username"]
                except (IndexError, KeyError):
                    username = None
        else:
            username = target
            row = db.client_by_username(username)
            if row:
                try:
                    tg_id = row["tg_id"]
                except (IndexError, KeyError):
                    tg_id = None
        if tg_id is None:
            await msg.reply_text(
                f"❌ Клиента <code>{esc(target)}</code> нет в базе.\n\n"
                "Сначала клиент должен сам нажать /start у бота — после этого "
                "появится в /clients и его можно привязать.\n\n"
                f"Возврат: /start или нажми ниже.",
                parse_mode=ParseMode.HTML,
                reply_markup=kb([[btn("← к роутеру", f"r:{rid}")]]),
            )
            return
        try:
            db.bind(tg_id, rid)
            db.audit(u.id, u.username, rid, "owner_add",
                     f"tg_id={tg_id} @{username or '—'}", "ok")
            await msg.reply_text(
                f"✅ <code>@{esc(username or str(tg_id))}</code> привязан к <b>{rid}</b>.",
                parse_mode=ParseMode.HTML,
                reply_markup=kb([
                    [btn("👥 К списку владельцев", f"own:list:{rid}")],
                    [btn("← к роутеру", f"r:{rid}")],
                ]),
            )
        except Exception as e:
            log.exception("owner_add")
            await msg.reply_text(f"❌ {esc(e)}")
        return

    # --- Stage 3 / Клиент пкт 8: routing add ---
    if state == "awaiting_routing_add":
        rid = ctx.user_data.get("state_rid")
        if not rid:
            ctx.user_data.pop("state", None)
            return
        if not client_owns_router(ctx, u.id, rid):
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return
        # Парсим список: один на строку, lowercase.
        raw_lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
        if not raw_lines:
            await msg.reply_text(
                "❌ Ничего не понял. Пришли домены по одному на строку.",
                reply_markup=kb([[btn("← назад", f"rt:menu:{rid}")]]),
            )
            return

        # Валидация
        bad: list[str] = []
        good: list[str] = []
        for d in raw_lines:
            # strip schemes/trailing slashes для дружелюбия
            d = re.sub(r"^(?:https?://)?(?:www\.)?", "", d)
            d = d.split("/")[0].split("?")[0].split(":")[0].strip()
            ok_dom, err = validate_domain(d)
            if ok_dom:
                if d not in good:
                    good.append(d)
            else:
                bad.append(f"{d}: {err}")
        if bad and not good:
            await msg.reply_text(
                "❌ Ни одного валидного домена:\n" +
                "\n".join(f"• <code>{esc(x)}</code>" for x in bad[:10]),
                parse_mode=ParseMode.HTML,
                reply_markup=kb([[btn("← назад", f"rt:menu:{rid}")]]),
            )
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return

        # Получаем текущее состояние, сливаем added
        ok, server, added, removed, err = await _rt_current_state(db, rid, ctx, u.id)
        if not ok:
            await msg.reply_text(f"❌ {esc(err)}")
            ctx.user_data.pop("state", None)
            ctx.user_data.pop("state_rid", None)
            return
        existing = {x.lower() for x in server}
        in_added = {x.lower() for x in added}
        in_removed = {x.lower() for x in removed}
        really_new: list[str] = []
        dup: list[str] = []
        for d in good:
            dl = d.lower()
            if dl in in_added:
                dup.append(d)
                continue
            if dl in existing and dl not in in_removed:
                dup.append(d)
                continue
            if dl in in_removed:
                # Был отмечен на удаление — просто отменяем удаление.
                removed = [r for r in removed if r.lower() != dl]
            else:
                added.append(d)
                really_new.append(d)

        # Rate-limit клиенту: только за действительно новые.
        role = user_role(ctx, u.id)
        if role != "admin" and really_new:
            limit = cfg["rate_limits"].get("routing_add_per_day", 20)
            if limit > 0:
                allowed: list[str] = []
                rejected = 0
                for d in really_new:
                    if db.rate_check_and_inc(u.id, "routing_add", limit):
                        allowed.append(d)
                    else:
                        rejected += 1
                if rejected:
                    # Откатываем: убираем последние rejected из added.
                    keep_lowers = {a.lower() for a in allowed}
                    added = [
                        a for a in added
                        if a.lower() not in {x.lower() for x in really_new}
                        or a.lower() in keep_lowers
                    ]
                    really_new = allowed
                    await msg.reply_text(
                        f"⚠ Лимит {limit}/день на добавления исчерпан. "
                        f"Добавлено {len(allowed)} из {len(allowed) + rejected}."
                    )
        db.pending_routing_save(u.id, rid, added, removed)

        ctx.user_data.pop("state", None)
        ctx.user_data.pop("state_rid", None)

        report_lines = [
            f"📋 <b>{rid}</b> — правки приняты",
            f"Новых в буфере: <b>{len(really_new)}</b>",
        ]
        if dup:
            report_lines.append(f"Уже было: {len(dup)}")
        if bad:
            report_lines.append(f"Отклонено невалидных: {len(bad)}")
        report_lines.append("")
        report_lines.append("Открой «📋 Маршрутизация» для применения.")
        await msg.reply_text(
            "\n".join(report_lines),
            parse_mode=ParseMode.HTML,
            reply_markup=kb([
                [btn("📋 К меню маршрутизации", f"rt:menu:{rid}")],
                [btn("← к роутеру", f"r:{rid}")],
            ]),
        )
        return

    # --- по умолчанию ---
    await cmd_start(update, ctx)


# =============================================================================
# Background jobs: poll / digest / backup
# =============================================================================

async def job_poll(ctx: ContextTypes.DEFAULT_TYPE):
    await _do_poll(ctx.application)


async def _do_poll(app: Application):
    log = app.bot_data["log"]
    db: DB = app.bot_data["db"]
    cfg: dict = app.bot_data["cfg"]
    try:
        rcfg = load_r_config(cfg)
        app.bot_data["r_config"] = rcfg
    except Exception as e:
        log.error("load r_config: %s", e)
        return
    routers = discover(rcfg)
    # Stage 2 / A1: для роутеров в transit/maintenance не идём по SSH —
    # они либо в пути (физически не подключены), либо на техработах
    # (преднамеренное «не трогать»). Иначе будут тонны false-positive
    # offline-уведомлений и забитый thread-пул.
    skip_lifecycle = set()
    for st in db.all_states():
        try:
            ls = st["lifecycle_status"]
        except (IndexError, KeyError):
            ls = None
        if ls in ("transit", "maintenance"):
            skip_lifecycle.add(st["router_id"])
    pollable_routers = [r for r in routers if r.id not in skip_lifecycle]
    results = poll_all(
        pollable_routers,
        rcfg["ssh"],
        workers=cfg["poll"]["parallel_workers"],
    )
    overrides = rcfg.get("overrides") or {}
    # Отметить знакомые offline роутеры
    known = set(all_slots_from_config(rcfg)) | {r.id for r in routers}
    online_ids = {r.id for r in pollable_routers}
    for rid in sorted(known):
        # Stage 2 / A1: lifecycle-роутеры обновляем только меткой, поллинг не
        # трогает их online-флаг (был = остаётся; админ управляет вручную).
        if rid in skip_lifecycle:
            continue
        label = overrides.get(rid, "") or ""
        if rid in online_ids:
            res = results.get(rid)
            if res is None:
                continue
            # Stage 1: пробрасываем все новые поля PollResult в БД, чтобы
            # _show_router и сводки могли их показывать сразу после полла.
            db.update_state(
                rid,
                label,
                online=res.online,
                podkop_status=res.podkop,
                uptime=res.uptime,
                wan_ip=res.wan_ip,
                active_vless=res.vless,
                sing_running=res.sing_running,
                nft_table=res.nft_table,
                local_ip=res.local_ip,
                egress_ip=res.egress_ip,
                egress_country=res.egress_country,
                egress_country_iso=res.egress_country_iso,
                egress_city=res.egress_city,
                egress_asn_org=res.egress_asn_org,
                hw_model=res.hw_model,
                openwrt_version=res.openwrt_version,
                podkop_version=res.podkop_version,
                singbox_version=res.singbox_version,
            )
        else:
            # Offline: новые поля не трогаем — COALESCE в UPSERT сохранит
            # последние известные значения (страна/модель не обнуляются).
            db.update_state(rid, label, False, None, None, None, None)
    log.info("poll: %d routers, %d online", len(known), len(online_ids))


def _build_digest(ctx: ContextTypes.DEFAULT_TYPE | Application) -> str:
    app = ctx.application if hasattr(ctx, "application") else ctx
    db: DB = app.bot_data["db"]
    states = db.all_states()
    total = len(states)
    online = [s for s in states if s["online"]]
    offline = [s for s in states if not s["online"]]
    stopped = [s for s in online if s["podkop_status"] == "STOP"]

    since = (dt.datetime.utcnow() - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    history = db.history_since(since)
    went_off = [h for h in history if h["event"] == "offline"]
    came_on = [h for h in history if h["event"] == "online"]
    vless_changes = [h for h in history if h["event"] == "vless_change"]

    lines = [
        f"📊 <b>Ежедневная сводка</b> ({dt.datetime.utcnow().strftime('%d.%m')})\n",
        f"Всего: <b>{total}</b>  ·  🟢 online: {len(online)}  ·  🔴 offline: {len(offline)}  ·  🟡 podkop-STOP: {len(stopped)}\n",
    ]
    if went_off:
        lines.append(f"\n🔴 Упали за сутки ({len(went_off)}):")
        for h in went_off[-10:]:
            lines.append(f"  • {h['router_id']} ({h['at']})")
    if came_on:
        lines.append(f"\n🟢 Поднялись ({len(came_on)}):")
        for h in came_on[-10:]:
            lines.append(f"  • {h['router_id']} ({h['at']})")
    if stopped:
        lines.append(f"\n🟡 podkop STOP:")
        for s in stopped[:10]:
            lines.append(f"  • {s['router_id']} ({s['label'] or '—'})")
    if vless_changes:
        lines.append(f"\n🔗 Смены VLESS ({len(vless_changes)}):")
        for h in vless_changes[-10:]:
            lines.append(f"  • {h['router_id']} ({h['at']})")
    return "\n".join(lines)


async def job_digest(ctx: ContextTypes.DEFAULT_TYPE):
    cfg: dict = ctx.application.bot_data["cfg"]
    if not cfg["digest"]["enabled"]:
        return
    text = _build_digest(ctx)
    for admin_id in cfg["admins"]:
        try:
            await ctx.bot.send_message(admin_id, text, parse_mode=ParseMode.HTML)
        except Exception:
            pass


def _make_backup(cfg: dict) -> Path:
    backups = Path(cfg["paths"]["backups"])
    backups.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    archive = backups / f"r-bot-{ts}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        db_path = Path(cfg["paths"]["db"])
        if db_path.exists():
            tf.add(db_path, arcname="bot.db")
        # bot.yaml копируем без поля token (безопасность — если архив где-то утечёт)
        yaml_path = Path("/etc/r/bot.yaml")
        if yaml_path.exists():
            safe = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            if isinstance(safe, dict):
                safe["token"] = "REDACTED"
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
                yaml.safe_dump(safe, tmp, allow_unicode=True)
                tmp_path = tmp.name
            tf.add(tmp_path, arcname="bot.yaml.redacted")
            os.unlink(tmp_path)
    # Удалить старые
    keep = cfg["backup"].get("keep_days", 14)
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=keep)
    for f in backups.glob("r-bot-*.tar.gz"):
        try:
            if dt.datetime.utcfromtimestamp(f.stat().st_mtime) < cutoff:
                f.unlink()
        except Exception:
            pass
    return archive


async def job_backup_daily(ctx: ContextTypes.DEFAULT_TYPE):
    cfg: dict = ctx.application.bot_data["cfg"]
    log = ctx.application.bot_data["log"]
    try:
        archive = _make_backup(cfg)
        log.info("daily backup: %s", archive)
    except Exception:
        log.exception("daily backup")


async def job_backup_weekly(ctx: ContextTypes.DEFAULT_TYPE):
    cfg: dict = ctx.application.bot_data["cfg"]
    log = ctx.application.bot_data["log"]
    if not cfg["backup"]["weekly_telegram"]:
        return
    try:
        archive = _make_backup(cfg)
        for admin_id in cfg["admins"]:
            with open(archive, "rb") as f:
                await ctx.bot.send_document(
                    admin_id,
                    document=InputFile(f, filename=archive.name),
                    caption="Еженедельный бэкап r-bot",
                )
        log.info("weekly backup sent to %d admins", len(cfg["admins"]))
    except Exception:
        log.exception("weekly backup")


async def job_cleanup_runs(ctx: ContextTypes.DEFAULT_TYPE):
    cfg: dict = ctx.application.bot_data["cfg"]
    runs = Path(cfg["paths"]["runs"])
    if not runs.exists():
        return
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=30)
    for p in runs.rglob("*.log"):
        try:
            if dt.datetime.utcfromtimestamp(p.stat().st_mtime) < cutoff:
                p.unlink()
        except Exception:
            pass


async def job_audit_retention(ctx: ContextTypes.DEFAULT_TYPE):
    """Stage 3 / A7: дропаем audit старше cfg.audit_retention_days."""
    cfg: dict = ctx.application.bot_data["cfg"]
    db: DB = ctx.application.bot_data["db"]
    log = ctx.application.bot_data["log"]
    days = int(cfg.get("audit_retention_days", 90))
    try:
        deleted = db.audit_retention_cleanup(days=days)
        log.info("audit retention: dropped %d rows (>%d days)", deleted, days)
    except Exception:
        log.exception("audit retention")


async def job_client_logs_retention(ctx: ContextTypes.DEFAULT_TYPE):
    """Stage 3 / S3-4: дропаем клиентские логи + файлы старше
    cfg.client_logs_retention_days (30 по умолчанию)."""
    cfg: dict = ctx.application.bot_data["cfg"]
    db: DB = ctx.application.bot_data["db"]
    log = ctx.application.bot_data["log"]
    days = int(cfg.get("client_logs_retention_days", 30))
    try:
        paths = db.client_logs_retention_cleanup(days=days)
    except Exception:
        log.exception("client logs retention (db)")
        return
    removed = 0
    for p in paths:
        try:
            if p:
                fp = Path(p)
                if fp.exists():
                    fp.unlink()
                    removed += 1
        except Exception:
            log.exception("unlink %s", p)
    log.info("client logs retention: db=%d files=%d (>%d days)",
             len(paths), removed, days)


async def job_auto_update(ctx: ContextTypes.DEFAULT_TYPE):
    cfg: dict = ctx.application.bot_data["cfg"]
    if not cfg["auto_update"]["enabled"]:
        return
    log = ctx.application.bot_data["log"]
    repo_dir = cfg["auto_update"]["repo_dir"]
    try:
        proc = subprocess.run(
            ["git", "-C", repo_dir, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0 and "Already up to date" not in (proc.stdout or ""):
            log.info("auto_update: pulled new commits, update.sh will be needed")
            for admin_id in cfg["admins"]:
                try:
                    await ctx.bot.send_message(
                        admin_id,
                        f"🔄 Появились новые коммиты в репо. Запусти <code>sudo bash {repo_dir}/scripts/update.sh</code>",
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass
    except Exception:
        log.exception("auto_update")


# =============================================================================
# Главный callback-диспатчер
# =============================================================================

async def cb_router_msgs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Универсальный handler для callback_query — роутит по префиксу."""
    q = update.callback_query
    if not q or not q.data:
        return
    data = q.data

    try:
        if data == "menu:main":
            await cmd_start(update, ctx)
            return
        if data == "poll:now":
            await q.answer("Обновляю...")
            await _do_poll(ctx.application)
            await cmd_start(update, ctx)
            return
        # list:all:0 / list:bad:1 ... (Stage 2: + transit, maint)
        # Stage 2 / A1: заглушка для будущей кнопки поиска (без page-suffix).
        if data == "list:search_stub":
            await cb_list_search_stub(update, ctx)
            return
        if data.startswith("list:"):
            await cb_list(update, ctx)
            return
        if data.startswith("r:"):
            await cb_router(update, ctx)
            return
        if data.startswith("act:"):
            await cb_action(update, ctx)
            return
        if data.startswith("do:"):
            await cb_do(update, ctx)
            return
        if data.startswith("log:send:"):
            await cb_log_send(update, ctx)
            return
        if data.startswith("vless:pick:"):
            await cb_vless_pick(update, ctx)
            return
        if data.startswith("vless:conf:"):
            await cb_vless_conf(update, ctx)
            return
        if data.startswith("vless:apply:"):
            await cb_vless_apply(update, ctx)
            return
        # Stage 2 / A2: custom VLESS
        if data.startswith("vless:custom:"):
            await cb_vless_custom_start(update, ctx)
            return
        if data.startswith("vless:capply:"):
            await cb_vless_custom_confirm(update, ctx)
            return
        if data.startswith("vless:pool:"):
            await cb_vless_pool_return(update, ctx)
            return
        # Stage 2 / клиент пкт 7: WiFi menu + edit
        if data.startswith("wifi:menu:"):
            await cb_wifi_menu(update, ctx)
            return
        if data.startswith("wifi:show:"):
            await cb_wifi_show_password(update, ctx)
            return
        if data.startswith("wifi:edit:"):
            await cb_wifi_edit_start(update, ctx)
            return
        if data.startswith("wifi:wapply:"):
            await cb_wifi_edit_confirm(update, ctx)
            return
        # Stage 2 / A9: owners management
        if data.startswith("own:list:"):
            await cb_owners_list(update, ctx)
            return
        if data.startswith("own:add:"):
            await cb_owner_add_start(update, ctx)
            return
        if data.startswith("own:rm:"):
            await cb_owner_remove(update, ctx)
            return
        if data == "pool:list":
            await cb_pool_list(update, ctx)
            return
        if data == "pool:add":
            await cb_pool_add(update, ctx)
            return
        if data.startswith("pool:del:"):
            await cb_pool_del_page(update, ctx)
            return
        if data.startswith("pool:del_one:"):
            await cb_pool_del_one(update, ctx)
            return
        if data.startswith("pool:bind:"):
            await cb_pool_bind(update, ctx)
            return
        if data.startswith("pool:bind_r:"):
            await cb_pool_bind_r(update, ctx)
            return
        if data.startswith("pool:bind_t:"):
            await cb_pool_bind_toggle(update, ctx)
            return
        if data.startswith("pool:bind_clr:"):
            await cb_pool_bind_clear(update, ctx)
            return
        if data == "cli:list":
            await cb_clients_list(update, ctx)
            return
        if data == "req:list":
            await cb_requests_list(update, ctx)
            return
        if data.startswith("req:view:"):
            await cb_request_view(update, ctx)
            return
        if data.startswith("req:ok:") or data.startswith("req:no:"):
            await cb_request_decide(update, ctx)
            return
        if data == "inv:list":
            await cb_invites_list(update, ctx)
            return
        if data.startswith("inv:new:"):
            await cb_invite_new_pick_router(update, ctx)
            return
        if data.startswith("inv:gen:"):
            await cb_invite_generate(update, ctx)
            return
        if data.startswith("label:ren:"):
            await cb_label_rename(update, ctx)
            return
        if data.startswith("label:del:"):
            await cb_label_delete(update, ctx)
            return
        if data.startswith("label:delgo:"):
            await cb_label_delete_go(update, ctx)
            return
        if data == "mass:menu":
            await cb_mass_menu(update, ctx)
            return
        if data in ("mass:pall", "mass:pfail", "mass:rall"):
            await cb_mass_confirm(update, ctx)
            return
        if data == "cfg:menu":
            await cb_cfg_menu(update, ctx)
            return
        if data.startswith("cfg:audit"):
            await cb_cfg_audit(update, ctx)
            return
        if data == "cfg:backup":
            await cb_cfg_backup(update, ctx)
            return
        if data == "cfg:update":
            await cb_cfg_update(update, ctx)
            return
        if data == "cfg:digest_test":
            await cb_cfg_digest_test(update, ctx)
            return
        if data == "guest:code":
            await cb_guest_code(update, ctx)
            return
        if data == "guest:request":
            await cb_guest_request(update, ctx)
            return

        # Stage 3 / Client пкт 8: маршрутизация
        if data.startswith("rt:menu:"):
            await cb_rt_menu(update, ctx)
            return
        if data.startswith("rt:add:"):
            await cb_rt_add_start(update, ctx)
            return
        if data.startswith("rt:rmlist:"):
            await cb_rt_remove_list(update, ctx)
            return
        if data.startswith("rt:rmone:") or data.startswith("rt:rmoneI:"):
            await cb_rt_rmone(update, ctx)
            return
        if data.startswith("rt:reset:"):
            await cb_rt_reset(update, ctx)
            return
        if data.startswith("rt:preview:"):
            await cb_rt_preview(update, ctx)
            return
        if data.startswith("rt:apply:"):
            await cb_rt_apply(update, ctx)
            return
        # Stage 3 / Client пкт 2: отправить лог админу
        if data.startswith("lga:"):
            await cb_log_to_admin(update, ctx)
            return
        if data.startswith("clog:read:"):
            await cb_clog_read(update, ctx)
            return
        if data.startswith("clog:view:"):
            await cb_client_log_view(update, ctx)
            return
        if data.startswith("clog:file:"):
            await cb_client_log_file(update, ctx)
            return
        if data.startswith("clog:list"):
            await cb_client_logs_list(update, ctx)
            return
        # Stage 3 / A7: audit UI
        if data.startswith("aud:r:"):
            await cb_audit_router(update, ctx)
            return
        if data.startswith("aud:csv:"):
            await cb_audit_csv(update, ctx)
            return
        # Stage 3 / A8: глобальный тест
        if data == "gt:run":
            await cb_global_test(update, ctx)
            return
        # noop — заглушка для счётчиков страниц
        if data == "noop":
            await q.answer()
            return

        await q.answer("Неизвестная команда", show_alert=False)
    except Exception as e:
        log = ctx.application.bot_data.get("log")
        if log:
            log.exception("callback %s", data)
        try:
            await q.answer(f"Ошибка: {e}", show_alert=True)
        except Exception:
            pass


# =============================================================================
# /cancel, /help и прочие команды
# =============================================================================

async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Отменено.")
    await cmd_start(update, ctx)


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Команды:\n"
        "/start — главное меню\n"
        "/cancel — отменить ввод\n"
        "/request idNN сообщение — подать заявку на привязку\n"
        "/code XX-YYYY — активировать invite-код\n"
    )


async def cmd_request(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["state"] = "awaiting_request"
    args_text = " ".join(ctx.args or [])
    if args_text:
        # обрабатываем прямо как ввод
        update.effective_message.text = args_text
        await handle_text(update, ctx)
        return
    await update.message.reply_text(
        "Формат: /request idNN сообщение\nНапр.: /request id07 Вася, меня прислал Ярослав",
    )


async def cmd_code(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if ctx.args:
        ctx.user_data["state"] = "awaiting_code"
        update.effective_message.text = ctx.args[0]
        await handle_text(update, ctx)
    else:
        ctx.user_data["state"] = "awaiting_code"
        await update.message.reply_text("Пришли код приглашения текстом.")


# =============================================================================
# Init DB (seed admins, первичный polling)
# =============================================================================

def init_db(cfg: dict) -> DB:
    db = DB(cfg["paths"]["db"])
    # seed admins
    for aid in cfg.get("admins", []):
        db.set_admin(int(aid))
    # seed clients из bot.yaml (если есть)
    for tg_id, info in (cfg.get("clients") or {}).items():
        try:
            tg_id = int(tg_id)
        except Exception:
            continue
        role = (info or {}).get("role", "client")
        note = (info or {}).get("note", "")
        db.upsert_client(tg_id, None, None, role=role, note=note)
        for rid in (info or {}).get("routers") or []:
            db.bind(tg_id, rid)
    return db


# =============================================================================
# Main
# =============================================================================

def _parse_hhmm(s: str) -> dt.time:
    h, m = s.split(":")
    return dt.time(int(h), int(m))


def _day_of_week_number(name: str) -> int:
    """JobQueue.run_daily: 0=Sunday ... 6=Saturday (по API python-telegram-bot)."""
    mapping = {"Sun": 0, "Mon": 1, "Tue": 2, "Wed": 3, "Thu": 4, "Fri": 5, "Sat": 6}
    return mapping.get(name, 0)


async def _post_init(app: Application):
    log = app.bot_data["log"]
    # Первичный polling при старте
    try:
        await _do_poll(app)
    except Exception:
        log.exception("initial poll")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=DEFAULT_CFG_PATH)
    parser.add_argument("--init-db", action="store_true", help="Инициализировать БД и выйти")
    args = parser.parse_args()

    cfg = load_cfg(args.config)
    log = setup_logging(cfg["paths"]["log"])
    log.info("r-bot v%s starting, config=%s", VERSION, args.config)

    db = init_db(cfg)
    rcfg = load_r_config(cfg)

    if args.init_db:
        log.info("--init-db done: %d clients seeded", len(db.all_clients()))
        print(f"БД инициализирована: {cfg['paths']['db']}")
        print(f"Admin(s): {cfg['admins']}")
        return

    Path(cfg["paths"]["runs"]).mkdir(parents=True, exist_ok=True)
    Path(cfg["paths"]["backups"]).mkdir(parents=True, exist_ok=True)

    app = (
        Application.builder()
        .token(cfg["token"])
        .post_init(_post_init)
        .build()
    )
    app.bot_data["cfg"] = cfg
    app.bot_data["r_config"] = rcfg
    app.bot_data["db"] = db
    app.bot_data["log"] = log

    # Хэндлеры
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("request", cmd_request))
    app.add_handler(CommandHandler("code", cmd_code))
    app.add_handler(CallbackQueryHandler(cb_router_msgs))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Фоновые задачи
    jq = app.job_queue
    if jq is None:
        log.error("JobQueue не инициализирован. Установи `python-telegram-bot[job-queue]`.")
        sys.exit(1)

    tz = ZoneInfo(cfg["digest"]["timezone"])

    # Polling каждые N минут
    jq.run_repeating(job_poll, interval=cfg["poll"]["interval_minutes"] * 60, first=30)

    # Daily digest
    if cfg["digest"]["enabled"]:
        dt_time = _parse_hhmm(cfg["digest"]["time"]).replace(tzinfo=tz)
        jq.run_daily(job_digest, time=dt_time)

    # Daily backup
    dt_bk = _parse_hhmm(cfg["backup"]["daily_cron"]).replace(tzinfo=tz)
    jq.run_daily(job_backup_daily, time=dt_bk)

    # Weekly backup to telegram
    if cfg["backup"]["weekly_telegram"]:
        dt_wk = _parse_hhmm(cfg["backup"]["weekly_time"]).replace(tzinfo=tz)
        day_n = _day_of_week_number(cfg["backup"]["weekly_day"])
        jq.run_daily(job_backup_weekly, time=dt_wk, days=(day_n,))

    # Cleanup старых run-логов
    jq.run_daily(job_cleanup_runs, time=dt.time(2, 30, tzinfo=tz))

    # Stage 3 / A7: retention для audit (по умолчанию 90 дней)
    jq.run_daily(job_audit_retention, time=dt.time(4, 0, tzinfo=tz))

    # Stage 3 / S3-4: retention клиентских логов (по умолчанию 30 дней)
    jq.run_daily(job_client_logs_retention, time=dt.time(4, 15, tzinfo=tz))

    # Auto-update (если вкл)
    if cfg["auto_update"]["enabled"]:
        dt_au = _parse_hhmm(cfg["auto_update"]["time"]).replace(tzinfo=tz)
        jq.run_daily(job_auto_update, time=dt_au)

    log.info(
        "jobs: poll=%dmin, digest=%s, backup_daily=%s, auto_update=%s",
        cfg["poll"]["interval_minutes"],
        cfg["digest"]["time"] if cfg["digest"]["enabled"] else "off",
        cfg["backup"]["daily_cron"],
        "on" if cfg["auto_update"]["enabled"] else "off",
    )

    log.info("starting polling...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
