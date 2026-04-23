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
    do_get_vless,
    do_global_check,
    do_info,
    do_logread,
    do_ping,
    do_podkop_logs,
    do_podkop_restart,
    do_reboot,
    do_set_vless,
    parse_vless,
    poll_all,
    poll_router,
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
    },
    "rate_limits": {
        "reboot_per_day": 5,
        "podkop_restart_per_day": 10,
        "vless_change_per_day": 20,
        "global_check_per_day": 50,
    },
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
    rc.setdefault("web_port_range", [10001, 10099])
    rc.setdefault("ssh_port_range", [11001, 11099])
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


def status_icon(online: bool, podkop: str | None) -> str:
    if not online:
        return "🔴"
    if podkop == "RUN":
        return "🟢"
    if podkop == "STOP":
        return "🟡"
    return "⚪"


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
    return kb(
        [
            [btn("📊 Все роутеры", "list:all:0"), btn("⚠️ Проблемные", "list:bad:0")],
            [btn("👥 Клиенты", "cli:list"), btn(req_label, "req:list")],
            [btn("🎟 Коды", "inv:list"), btn("🔗 VLESS-пул", "pool:list")],
            [btn("🔔 Mass", "mass:menu"), btn("⚙️ Настройки", "cfg:menu")],
            [btn("🔄 Обновить данные", "poll:now")],
        ]
    )


def kb_main_client(db: DB, tg_id: int) -> InlineKeyboardMarkup:
    rids = db.client_routers(tg_id)
    rows = []
    for rid in rids:
        st = db.get_state(rid)
        icon = status_icon(
            bool(st and st["online"]),
            st["podkop_status"] if st else None,
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


def kb_router_menu(rid: str, role: str) -> InlineKeyboardMarkup:
    rows = [
        [btn("🔄 Статус", f"r:{rid}"), btn("▶️ Проверить", f"act:{rid}:check")],
        [btn("🔧 Restart podkop", f"act:{rid}:pres"), btn("🔁 Reboot", f"act:{rid}:boot")],
        [btn("🔗 Сменить VLESS", f"vless:pick:{rid}:0")],
    ]
    if role == "admin":
        rows.append([btn("📜 Logs", f"act:{rid}:logs"), btn("📜 Podkop logs", f"act:{rid}:plogs")])
        rows.append([btn("ℹ️ Info", f"act:{rid}:info")])
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
    db.upsert_client(u.id, u.username, u.first_name, role=db.get_client(u.id)["role"] if db.get_client(u.id) else "client")
    db.touch_seen(u.id)

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

PAGE_SIZE = 10


async def cb_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    _, mode, page_s = q.data.split(":")
    page = int(page_s)
    await _show_list(update, ctx, mode, page)


async def _show_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE, mode: str, page: int):
    db: DB = ctx.application.bot_data["db"]
    all_ids = all_router_ids(ctx)
    states = {s["router_id"]: s for s in db.all_states()}

    def matches(rid: str) -> bool:
        s = states.get(rid)
        online = bool(s and s["online"])
        podkop = s["podkop_status"] if s else None
        if mode == "all":
            return True
        if mode == "bad":
            return (not online) or (podkop == "STOP")
        if mode == "online":
            return online
        if mode == "offline":
            return not online
        return True

    filtered = [r for r in all_ids if matches(r)]
    total = len(filtered)
    start = page * PAGE_SIZE
    chunk = filtered[start : start + PAGE_SIZE]

    rcfg: dict = ctx.application.bot_data["r_config"]
    overrides = rcfg.get("overrides") or {}

    rows = []
    for rid in chunk:
        s = states.get(rid)
        online = bool(s and s["online"])
        podkop = s["podkop_status"] if s else None
        icon = status_icon(online, podkop)
        label = overrides.get(rid) or (s["label"] if s and s["label"] else "")
        short = f"{icon} {rid}" + (f" — {label[:24]}" if label else "")
        rows.append([btn(short, f"r:{rid}")])

    nav = []
    if page > 0:
        nav.append(btn("← назад", f"list:{mode}:{page-1}"))
    if start + PAGE_SIZE < total:
        nav.append(btn("вперёд →", f"list:{mode}:{page+1}"))
    if nav:
        rows.append(nav)

    mode_row = [
        btn("Все" + (" •" if mode == "all" else ""), "list:all:0"),
        btn("Проблемные" + (" •" if mode == "bad" else ""), "list:bad:0"),
        btn("Online" + (" •" if mode == "online" else ""), "list:online:0"),
        btn("Offline" + (" •" if mode == "offline" else ""), "list:offline:0"),
    ]
    rows.append(mode_row)
    rows.append([btn("← Главная", "menu:main")])

    text = (
        f"<b>Роутеры ({mode})</b>\n"
        f"Показано {len(chunk)} из {total}\n"
        f"Страница {page+1}/{max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)}"
    )
    await reply_or_edit(update, text, kb(rows))


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

    if st:
        icon = status_icon(bool(st["online"]), st["podkop_status"])
        status = "online" if st["online"] else "offline"
        podkop = st["podkop_status"] or "—"
        up = st["uptime"] or "—"
        wan = st["wan_ip"] or "—"
        last = st["last_poll_at"] or "—"
        text = (
            f"<b>{rid}</b> — {esc(label)}\n"
            f"{icon} {status}\n"
            f"podkop: <b>{esc(podkop)}</b>\n"
            f"uptime: {esc(up)}\n"
            f"WAN: <code>{esc(wan)}</code>\n"
            f"последний опрос: {esc(last)}"
        )
    else:
        text = (
            f"<b>{rid}</b> — {esc(label)}\n"
            "пока не опрошен. Нажми «Обновить статус» или подожди polling."
        )

    await reply_or_edit(update, text, kb_router_menu(rid, role))


# =============================================================================
# Действия на роутере: confirm + execute
# =============================================================================

ACTION_LABELS = {
    "boot": ("Reboot", "перезагрузить роутер", "reboot_per_day"),
    "pres": ("Restart podkop", "перезапустить podkop", "podkop_restart_per_day"),
    "check": ("Global check", "запустить global_check", "global_check_per_day"),
    "info": ("Info", "показать info", None),
    "logs": ("Logread", "показать logread", None),
    "plogs": ("Podkop logs", "показать podkop logs", None),
}


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

    # действия read-only — без подтверждения
    if act in ("info", "logs", "plogs", "check"):
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
            kb_ = kb(
                [
                    [btn("📄 Полный лог", f"log:send:{rid}:{log_path.name}")],
                    [btn("🔁 Повторить", f"act:{rid}:check"), btn("← назад", f"r:{rid}")],
                ]
            )
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
    rows = [
        [btn("📜 Журнал (audit)", "cfg:audit:0")],
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
    results = poll_all(
        routers,
        rcfg["ssh"],
        workers=cfg["poll"]["parallel_workers"],
    )
    overrides = rcfg.get("overrides") or {}
    # Отметить знакомые offline роутеры
    known = set(all_slots_from_config(rcfg)) | {r.id for r in routers}
    online_ids = {r.id for r in routers}
    for rid in sorted(known):
        label = overrides.get(rid, "") or ""
        if rid in online_ids:
            res = results.get(rid)
            if res is None:
                continue
            db.update_state(
                rid,
                label,
                online=res.online,
                podkop_status=res.podkop,
                uptime=res.uptime,
                wan_ip=res.wan_ip,
                active_vless=res.vless,
            )
        else:
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
        # list:all:0 / list:bad:1 ...
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
