# Stage 1 — обзор перед мерджем

Ветка: `rework/stage-1` (локально, ещё не запушена)
Файлы: `bot/router.py`, `bot/db.py`, `bot/r_bot.py`
Объём: **+348 / −36** строк в трёх .py-файлах

Полный дифф: [STAGE-1.diff](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/STAGE-1.diff)
Исходник цели: [REWORK-SPEC.md](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/REWORK-SPEC.md)

---

## Что сделано в Stage 1

| Спек-пункт | Где правка | Что меняется |
|---|---|---|
| **Клиент пкт 1** — страна выхода | `router.py` POLL_SCRIPT, `_parse_egress_json`; `r_bot.py` `_country_flag`, `_show_router` | На строке выхода появляется флаг страны и город (для админа — ещё ASN). Источник — `ifconfig.co/json` через busybox-wget. |
| **Клиент пкт 3** — локальный IP | `router.py` POLL_SCRIPT (LOCAL=yandex), `_show_router` | Показывается «локальный IP» от провайдера (yandex.com), а не WAN-интерфейс (актуально для 4G CGNAT). Если yandex недоступен — фолбэк на старый WAN. |
| **Клиент пкт 4** — короткий VLESS | `r_bot.py` `_short_vless`, `_show_router` | Клиент видит только host из vless://; админ видит полный URL. |
| **Клиент пкт 5** — кнопка «Перезагрузить службу» | `r_bot.py` `kb_router_menu`, `ACTION_LABELS["pres"]` | «🔧 Restart podkop» → «🔄 Перезагрузить службу». Текст подтверждения: «Точно перезагрузить службу podkop?». |
| **Клиент пкт 6** — кнопка «Перезагрузить Роутер (рекомендуется)» | `r_bot.py` `kb_router_menu`, `ACTION_LABELS["boot"]` | «🔁 Reboot» → «♻️ Перезагрузить Роутер (рекомендуется)». |
| **Подкоп статус BYPASS** | `router.py` `_compute_podkop_status`; `r_bot.py` `status_icon` | Новый статус 🟡 BYPASS (sing-box живой, но трафик идёт мимо VLESS). STOP перекрашен в 🟠. |
| **id-формат до id999** | `router.py` `discover`, `_format_router_id` | id01…id99 двузначные, id100…id999 трёхзначные. Существующие id07…id99 не ломаются. |
| **Версии прошивки/podkop/sing-box** | `router.py` POLL_SCRIPT (MODEL/OPENWRT/PODKOPVER/SINGBOXVER), `_show_router` | Только для админа: блок «модель · OpenWrt · podkop · sing-box» внизу карточки. |
| **БД-миграция** | `db.py` `_migrate`, `update_state` | 12 новых колонок в `router_state`, добавляются через `ALTER TABLE` идемпотентно (PRAGMA table_info → ADD COLUMN if missing). UPSERT использует `COALESCE(excluded.X, router_state.X)` — оффлайн-полл не обнулит страну/модель. |
| **Polling-callsite** | `r_bot.py` `_do_poll` | Все новые поля PollResult прокидываются в `db.update_state(...)`. |

---

## Файл за файлом

### `bot/router.py` (+149 / −16)

- **POLL_SCRIPT** заменён целиком: один скрипт собирает uptime, sing-box pgrep, nftables PodkopTable, yandex local IP, ifconfig.co egress JSON, model/openwrt/podkop/singbox версии — за один SSH-раундтрип.
- Таймаут SSH 12 → **20** секунд (два внешних wget'а в худшем случае).
- `_section()` regex расширен до `[A-Z_]+` (поддержка PODKOPVER, SINGBOXVER).
- Новые: `_parse_egress_json`, `_compute_podkop_status`, `_format_router_id`.
- `discover()`: формула `num = p − ssh_lo + 1` (вместо `p % 100`, который ломался на 100+); диапазон 1…999.
- `PollResult` расширен на 12 полей (sing_running, nft_table, local_ip, egress_*, podkop_via_vless, hw_model, openwrt_version, podkop_version, singbox_version).

### `bot/db.py` (+90 / −2)

- Схема `router_state` дополнена 12 столбцами в CREATE TABLE.
- `_migrate()` — вызывается из `__init__` сразу после создания схемы; для каждой новой колонки `PRAGMA table_info` → `ALTER TABLE ADD COLUMN` если отсутствует. Безопасно для уже задеплоенной БД.
- `update_state()` — сигнатура расширена 12 опциональными параметрами с `None` по умолчанию (старые callsite не ломаются). UPSERT использует `COALESCE(excluded.X, router_state.X)` чтобы NULL не затирал ранее накопленные значения.

### `bot/r_bot.py` (+145 / −22)

- `load_r_config()` — диапазоны портов 10001…10999 / 11001…11999 (раньше …99).
- `status_icon()` — добавлен 🟡 BYPASS, STOP перекрашен в 🟠.
- Новые хелперы: `_country_flag(iso)` (DE → 🇩🇪 через regional indicator), `_short_vless(url)` (vless://… → host).
- `kb_router_menu` — кнопки «Перезагрузить службу» и «Перезагрузить Роутер (рекомендуется)».
- `ACTION_LABELS` — русские лейблы для audit/confirm-текста.
- `_show_router` — переписан: role-aware рендер карточки (флаг + город + ASN на egress; короткий/полный VLESS; версионный блок только админу).
- `_do_poll` — пробрасывает все новые поля `PollResult` в `db.update_state(...)`. Для offline-роутеров вызов оставлен как был — COALESCE сохранит старые значения страны/модели.

---

## Чего пока НЕ сделано (Stage 2 / Stage 3)

- Stage 2: A1 lifecycle-статусы и фильтры, A2 кастомный VLESS, A3 3-кнопки-в-ряд, клиент пкт 7 WiFi-меню, A9 «один клиент → N роутеров».
- Stage 3: клиент пкт 8 (роутинг), клиент пкт 2 (отправка лога админу), A6 push-уведомления, A7 audit-лог + retention, A8 новый формат Global test.

---

## Sanity-чек

- `python3 -m py_compile bot/r_bot.py bot/router.py bot/db.py` → OK.
- pycache в diff игнорируем — он был закоммичен в upstream (это отдельный hygiene-фикс, не часть Stage 1).

---

## Что дальше

1. Просмотри [STAGE-1.diff](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/STAGE-1.diff) или открой ветку `rework/stage-1` локально.
2. Дай добро — закоммичу одним коммитом «Stage 1: client UI + DB schema for new poll fields», запушу в `origin/rework/stage-1` и открою PR в `main`. Или несколькими коммитами по подпунктам — как скажешь.
3. После мерджа — переходим к Stage 2 (A1 lifecycle + A9 multi-binding в первую очередь).
