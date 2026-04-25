# Stage 3 — ревью

**Дата:** 24 апреля 2026
**Статус:** реализовано, скомпилировано, импорт-тест пройден, diff round-trip подтверждён.
**Базовое состояние:** `r-bot` после Stage 2 (ветка с STAGE-1.diff + STAGE-2.diff).
**Итоговый diff:** `docs/STAGE-3.diff` — 1912 строк, +1753 / −10.

---

## Что сделано в Stage 3

В REWORK-SPEC.md для Stage 3 было 5 независимых пунктов. Все закрыты.

### 1. Client пкт 8 — `📋 Маршрутизация` (uci user_domains, diff-preview, apply)

Клиент с правом на роутер видит в его меню кнопку **«📋 Маршрутизация»**. Внутри — персональный буфер правок (add/remove), diff-preview, и только одна кнопка «Применить», которая отправляет всё одной SSH-сессией.

Архитектура:
- **DB:** таблица `pending_routing (tg_id, router_id, added_json, removed_json, …)` — буфер не пропадает при рестарте бота (PK на паре).
- **Router.py:** `do_get_routing` (парсит `uci -q show podkop.main.user_domains`) и `do_set_routing` (валидирует регэкспом, запускает один шелл-скрипт с `uci del_list`/`add_list`, потом автоматически переключает `user_domain_list_type` на `dynamic`/`disabled` по `wc -w`, `uci commit podkop`, `/etc/init.d/podkop restart`). Всё через `shlex.quote`, против инъекции.
- **Валидация:** `validate_domain` — `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$` — отсеивает схемы, пути, порты, IP.
- **UI:** `cb_rt_menu` / `cb_rt_add_start` / `cb_rt_remove_list` (страницы по 10) / `cb_rt_rmone` / `cb_rt_preview` / `cb_rt_apply` / `cb_rt_reset`.
- **Callback-data 64 байта:** для длинных доменов fallback на `rt:rmoneI:<rid>:<idx>` (глобальный индекс в effective-списке).
- **Лимиты клиенту (админу — без):** `routing_add_per_day=20`, `routing_del_per_day=20`, потолок итогового списка `routing_max_domains=200`.
- **Text-handler:** состояние `awaiting_routing_add` парсит строки, зачищает схемы/пути, merge с `added`/`removed` (если домен был помечен на удаление — удаление отменяется; если уже есть в server — дубликат пропускается).
- **Audit:** запись `routing_apply` с JSON `{added, removed, size_after}`.

### 2. Client пкт 2 — `📤 Отправить лог админу`

В ответе глобального check-а, помимо «📄 Полный лог», появляется вторая кнопка «📤 Отправить лог админу».

- **Сбор лога:** `do_capture_client_log` — never throws; добавляет `logread | grep -Ei 'podkop|xray|sing-box' | tail -n 100`, `uci show podkop | head -n 50`, pgrep, nft к базовому global-check. Даже если роутер offline — прикладывает только global-check, файл всё равно создаётся.
- **Хранение:** `/var/lib/r-bot/client_logs/<rid>/log_<rid>_<ts>.txt` + запись в таблицу `client_logs(tg_id, username, router_id, log_path, preview, read_by_admin, created_at)`.
- **Доставка:** админам (всем из `cfg.admins` или `cfg.admin_chat_ids`, если задан) `send_document` + превью + кнопки «👁 Прочитано» и «📜 Аудит роутера».
- **Админ-UI:** пункт `📥 Логи от клиентов (N)` в `kb_main_admin` и в `cfg:menu` — с бейджем непрочитанных. Листинг `clog:list` c переключателем «все / только непрочитанные», просмотр `clog:view`, скачивание `clog:file`.
- **Retention:** `job_client_logs_retention` (04:15) — удаляет строки и файлы старше `client_logs_retention_days` (30 по умолчанию).
- **Лимит клиенту:** `send_log_per_day=5`.

### 3. A6 — push-уведомления админу

Помощник `_push_admins(ctx, text, reply_markup)` рассылает админам, все ошибки глушит (логируем). Триггеры:

- **Новый /start:** если `get_client(u.id) is None` и не админ, пушим «👋 Новый клиент /start … @username (tg_id, FirstName)» с кнопкой «👥 Клиенты».
- **WiFi-изменение клиентом:** в `cb_wifi_edit_confirm`, на успешный apply, если не админ — «📶 id07 (@user): сменён WiFi, SSID: old → new» + кнопка «📜 История».
- **Routing apply клиентом:** в `cb_rt_apply`, на успех, если не админ — «⚙ id07 (@user): обновлена маршрутизация +X / −Y (итог Z)» + «📜 История».

Специально **не** пушим onflip offline/online по поллу — 52 роутера × 4G-вспышки = спам. А вот лог-алерты и действия клиента — редкие и важные.

### 4. A7 — аудит-лог UI по роутеру + retention

В меню роутера у админа — кнопка «📜 Аудит роутера» (парно с «Info»). Callback `aud:r:<rid>:<page>`:

- Страница по 15 записей, пагинация ‹ N/M ›.
- Формат: `<time> · @user · action {✅|❌|·}` + `<args>` если длина < 80.
- **Экспорт CSV:** `aud:csv:<rid>` — собирает всё (`audit_all_by_router`), пишет через `csv.writer` в `io.StringIO`, отдаёт через `InputFile(BytesIO, filename=audit_<rid>.csv)`.
- **Retention:** `job_audit_retention` (04:00) — `audit_retention_cleanup(days=cfg.audit_retention_days)` (90 по умолчанию).

### 5. A8 — новый формат глобального теста

Кнопка «🧪 Глобальный тест» появилась в `kb_main_admin`, callback `gt:run` → `cb_global_test`.

- **Фильтр таргетов:** только online, без `lifecycle in (transit, maintenance)` — те, кого трогать нельзя.
- **Параллелизм:** `asyncio.Semaphore(GLOBAL_TEST_MAX_WORKERS=5)`, по-роутерный `asyncio.wait_for(..., timeout=35)`.
- **Проверки** (в `do_router_selftest`, одной SSH-сессией):
  - `SING` — `pgrep sing-box`
  - `TABLE` — `nft list tables` → PodkopTable
  - `LOCAL_IP` — yandex.ru/internet trace
  - `EGRESS` — `ifconfig.co/json`
  - `DNS_YT` — резолв youtube.com
  - `HTTP_YT` — HEAD youtube.com
- **Вердикт:**
  - `FAIL` — если упал SING или TABLE (роутер в прямом смысле не работает);
  - `WARN` — прочие проблемы (например, нет DNS-резолва, но sing+table живы);
  - `PASS` — всё зелёное.
- **Артефакт:** `paths.runs/global/global_test_YYYY-MM-DD_HH-MM.log`, отправляется админу как документ; в caption — summary (PASS/WARN/FAIL).

---

## Реестр touchpoints в коде

### `bot/db.py` (+121 строк, 641 → 798)
- В SCHEMA: таблицы `pending_routing`, `client_logs` (+3 индекса), `wifi_history` (+1 индекс).
- Методы: `audit_by_router`, `audit_count_by_router`, `audit_all_by_router`, `audit_retention_cleanup`, `pending_routing_{get,save,clear}`, `add_client_log`, `get_client_log`, `mark_client_log_read`, `client_logs_list`, `client_logs_unread_count`, `client_logs_retention_cleanup`, `add_wifi_history`.
- Миграция — без изменений (только новые таблицы via `CREATE TABLE IF NOT EXISTS`).

### `bot/router.py` (+290 строк, 844 → 1134)
- `_DOMAIN_RE`, `validate_domain`.
- `do_get_routing`, `do_set_routing` (с автоматическим `user_domain_list_type`).
- `do_capture_client_log`.
- `do_router_selftest`.

### `bot/r_bot.py` (+1030 строк, 3295 → 4325)
- Импорты дополнены: `do_capture_client_log`, `do_get_routing`, `do_router_selftest`, `do_set_routing`, `validate_domain`.
- `DEFAULT_CFG`: `paths.client_logs`, `rate_limits.{routing_add,routing_del,send_log}_per_day`, `audit_retention_days`, `routing_max_domains`, `client_logs_retention_days`, `admin_chat_ids`.
- `kb_main_admin`: +2 кнопки (🧪 Глобальный тест / 📥 Логи от клиентов c бейджем).
- `kb_router_menu`: +📋 Маршрутизация (всем), +📜 Аудит роутера (админу).
- `cmd_start`: A6 push «новый клиент /start».
- `cb_wifi_edit_confirm`: A6 push + `add_wifi_history`.
- `_execute_action` (check): добавлена кнопка «📤 Отправить лог админу».
- `cb_cfg_menu`: +📥 Логи от клиентов.
- Новые хендлеры: `cb_rt_*` (7), `cb_log_to_admin`, `cb_clog_read`, `cb_client_logs_list`, `cb_client_log_view`, `cb_client_log_file`, `cb_audit_router`, `cb_audit_csv`, `cb_global_test`.
- Новые helper'ы: `_rt_current_state`, `_rt_effective`, `_admin_chat_ids`, `_push_admins`.
- `handle_text`: состояние `awaiting_routing_add`.
- `cb_router_msgs`: диспатч для `rt:*`, `lga:`, `clog:*`, `aud:r:`, `aud:csv:`, `gt:run`, `noop`.
- Новые джобы: `job_audit_retention` (04:00), `job_client_logs_retention` (04:15).

---

## Проверки

### Компиляция

```
cd /opt/r-bot-src
python3 -m py_compile bot/db.py bot/router.py bot/r_bot.py
# → OK (тихий выход)
```

### Импорт-тест

```
python3 -c "import sys; sys.path.insert(0,'bot'); import db, router, r_bot; print('OK')"
# → OK
```

### Diff round-trip

Применение `STAGE-1.diff + STAGE-2.diff + STAGE-3.diff` к файлам из HEAD даёт побайтно совпадающие `bot/db.py`, `bot/router.py`, `bot/r_bot.py`. Команда:

```
diff -qr /tmp/stage3-applied/bot /sessions/.../bot
# → «Stage3 diff round-trips OK»
```

---

## Что осталось живьём проверить на VM

Stage 3 — существенная поверхностная переработка UX админа и клиента. Перед раскаткой на прод:

1. Запустить бота, открыть `/start`.
2. Под клиентом: открыть роутер → «📋 Маршрутизация» → «➕ Добавить» `test1.example` / `test2.example` → «✅ Применить». Проверить на роутере `uci show podkop.main.user_domains` и `uci show podkop.main.user_domain_list_type`.
3. Под клиентом: «▶ Проверить» → в ответе увидеть кнопку «📤 Отправить лог админу», нажать, проверить пуш и в админе «📥 Логи от клиентов (1)».
4. Под клиентом сменить WiFi → увидеть пуш админу.
5. Под админом «🧪 Глобальный тест» → дождаться `global_test_*.log`, проверить PASS/WARN/FAIL на тестовом кластере из 2-3 роутеров.
6. Под админом в меню роутера «📜 Аудит роутера» → пагинация → «📥 Экспорт CSV».
7. Дождаться 04:00 и 04:15 UTC — убедиться что retention-джобы пишут в лог `audit retention:` / `client logs retention:`.

---

## Известные компромиссы

- **Pending-буфер для routing один на роутер на клиента** — если клиент начал редактировать на двух устройствах одновременно, последнее write выиграет (на что мы явно идём, это осознанно; для двух админов-владельцев одного роутера это может создать гонку, но админы так делать не должны).
- **Push только при действиях клиента.** Если админ сам поменял WiFi/routing — себе же пуш слать нелепо, не шлём.
- **CSV экспорт аудита в оперативке.** Для роутера с 50k записей это всё равно <5 MB, но если когда-нибудь упрёмся — перейдём на streaming через temp-файл.
- **Глобальный тест пропускает transit/maintenance.** Это фича, а не баг: в maintenance трогать нельзя, а в transit роутер ещё не у клиента.
- **Retention удаляет только файлы, на которые есть записи в DB.** Если кто-то вручную написал в `client_logs/…` — такой файл останется. Это ожидаемо; housekeeping этого каталога — операторская задача.

---

## Следующие шаги

Stage 3 закрывает все пункты REWORK-SPEC. Возможные развития (вне scope):
- UI-подсказки в меню маршрутизации («что это?»), хелп-страница.
- Bulk-операции на уровне админа (apply набора правил сразу на N роутеров).
- Интеграция с клиент-UI в Mini-app, если решим делать WebApp.
- Alerting: уведомлять админа при N>5 FAIL-подряд в глобальных тестах.
