# Stage 2 — обзор перед мерджем

Ветка: `rework/stage-1` (поверх Stage 1, пока один рабочий дифф; можно раскатить двумя коммитами — Stage 1 + Stage 2, или одним)
Файлы: `bot/db.py`, `bot/router.py`, `bot/r_bot.py`
Объём Stage 2: **+1 262 / −34** строк (в дополнение к Stage 1 +348/−36)

Полный дифф Stage 2 (поверх Stage 1): [STAGE-2.diff](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/STAGE-2.diff)
Stage 1 дифф: [STAGE-1.diff](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/STAGE-1.diff)
Источник цели: [REWORK-SPEC.md](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/REWORK-SPEC.md)

---

## Что сделано в Stage 2

| Спек-пункт | Где правка | Что меняется |
|---|---|---|
| **A1** lifecycle-статусы | `db.py` новые колонки, `set_lifecycle`; `r_bot.py` `status_icon`, `_row_lifecycle`, `ACTION_LABELS`, `LIFECYCLE_ACTIONS`, ветка в `_execute_action`, lifecycle-кнопки в `kb_router_menu` | Добавлены статусы `transit` (🚚 в пути, клиент не видит) и `maintenance` (🛠 техработы, клиент видит плашку). Админ может переключать lifecycle даже на оффлайн-роутере — обработка идёт до offline-guard. Poll-лупер `_do_poll` пропускает такие роутеры (не бьёт по SSH, не шлёт false-offline алерты). |
| **A1** фильтры + `_show_list` | `r_bot.py` переписан `cb_list` / `_show_list` | Появились чипы-фильтры `online / offline / transit / maint / all` с количествами. Админ быстро видит, сколько в каком статусе. |
| **A2** Custom VLESS | `router.py` `validate_custom_vless`, `mask_vless_for_audit`; `db.py` `set_custom_vless`; `r_bot.py` `cb_vless_custom_start` / `…_confirm` / `cb_vless_pool_return` + guard в `cb_vless_apply` | Админ может ввести свой `vless://...` с reality-параметрами. Валидация: security=reality, pbk, sni — иначе отказ с пояснением. После применения — `in_pool=0`: ротация пула не перетрёт ключ. Кнопка «🔁 Вернуть в пул» снимает флаг. В audit пишется только маска (`***xxxx` для UUID/pbk). |
| **A3** 3 кнопки в ряд | `r_bot.py` `PAGE_SIZE=30`, `LIST_COLS=3`, `_owner_short_map` | 50 роутеров = 2 страницы. В подпись каждой кнопки подставлен короткий `@owner4` (если привязан 1 клиент) или счётчик `×N`. Single-SQL JOIN, один запрос на весь список. |
| **Клиент пкт 7** WiFi-меню | `router.py` `WifiInfo`, `do_get_wifi`, `do_set_wifi`; `db.py` `set_wifi_snapshot`; `r_bot.py` `cb_wifi_menu`, `cb_wifi_edit_start`, text-handlers `awaiting_wifi_ssid` / `awaiting_wifi_pwd`, `cb_wifi_edit_confirm`, `cb_wifi_show_password` | Кнопка «📶 WiFi» всем привязанным. Чтение: если онлайн — по SSH (uci show wireless), иначе снапшот из БД. Пароль маскирован; админ может «👁 Показать пароль» (с записью в audit). Редактирование FSM: SSID (1–32 B, без control-chars) → пароль (8–63 ASCII) → двойное подтверждение с предупреждением про отключение всех устройств. Применение: uci set на обоих радио (2.4GHz+5GHz), `wifi reload`. Лимит клиенту: **5 смен/сутки** (ключ `wifi_change_per_day` в cfg.rate_limits), админу без лимита. В audit — JSON `{ssid_before, ssid_after}`, **пароль не пишем**. |
| **A9** 1 аккаунт → N роутеров | `db.py` `client_by_username`; `r_bot.py` `cb_owners_list`, `cb_owner_add_start`, `cb_owner_remove`, text-handler `awaiting_owner_add` | Таблица `bindings` уже была N:N — UI достроен. Кнопка «👥 Владельцы» в меню роутера: список с ролями (👑 admin / 👤 client), кнопка «➕ Добавить» (принимает `@username` или `tg_id`), «✖ <имя>» на каждом владельце — снять привязку. Если клиента нет в базе — просьба сначала запустить /start у бота. Все действия в audit (`owner_add` / `owner_remove`). |
| **Transit-скрытие у клиента** | `r_bot.py` `kb_main_client` | Клиент не видит роутеры в статусе `transit` — они ещё едут. Когда админ нажмёт «✅ Активировать» — появятся. Maintenance видны с плашкой 🛠. |

---

## Файл за файлом

### `bot/db.py` (+70 / −1)

- Схема `router_state` + 6 колонок: `lifecycle_status`, `custom_vless_url`, `in_pool`, `wifi_ssid`, `wifi_encryption`, `wifi_updated_at`.
- `_migrate()` новые колонки дописаны в `new_cols` (идемпотентно на старых БД).
- Новые методы:
  - `set_lifecycle(router_id, status)` — UPSERT с валидацией `status ∈ {online,offline,transit,maintenance,None}`.
  - `set_custom_vless(router_id, url)` — ставит URL + флипает `in_pool` (0 когда URL задан, 1 когда None).
  - `set_wifi_snapshot(router_id, ssid, encryption)` — UPSERT снапшота с меткой времени.
  - `client_by_username(username)` — case-insensitive lookup для A9.

### `bot/router.py` (+194 / 0)

- `_VLESS_RE` + `validate_custom_vless(url) -> (ok, short, parsed)`: требуются `security=reality`, `pbk`, `sni`. Возвращает сокращённый вид `vless://…@host:port/?security=reality&sni=...` для подтверждения.
- `mask_vless_for_audit(url)` — UUID и pbk → `***<last4>`, остальное как есть.
- `WIFI_READ_SCRIPT` — один busybox-ash пробег через `uci show wireless` с маркерами секций.
- `@dataclass WifiInfo(ssid, key, encryption, consistent, note, error)` — результат чтения.
- `_wifi_section(out, name)` — парсер маркеров.
- `do_get_wifi(r, ssh_cfg)` — читает и сверяет два радио, выставляет `consistent` и `note`, если SSID/ключ разошлись.
- `do_set_wifi(r, ssh_cfg, ssid, password)` — валидация длин, uci set на обоих wifi-iface, `wifi reload`.

### `bot/r_bot.py` (+997 / −33)

- `import json` — для audit-JSON WiFi.
- Импорты из `router`: добавлены `do_get_wifi`, `do_set_wifi`, `mask_vless_for_audit`, `validate_custom_vless`.
- `status_icon(online, podkop, lifecycle=None)` — `transit`→🚚, `maintenance`→🛠 имеют приоритет над online/podkop.
- `_row_lifecycle(st)` — безопасный геттер (try/except IndexError,KeyError — для старых sqlite3.Row).
- `kb_main_client` — скрывает transit-роутеры.
- `kb_router_menu(rid, role, st=None)` — добавлены: `📶 WiFi` всем; `🔧 Custom VLESS` / `🔁 Вернуть в пул` (взаимоисключающие); lifecycle-кнопки (✅ Активировать / ▶ Снять техработы / 🛠 Техработы + 🚚 В пути); `👥 Владельцы` — админу.
- `_show_router` — role-aware рендер: клиент с transit-роутером получает сообщение «пока не активирован администратором», maintenance → плашка 🛠, админу виден маркер `🔧 custom VLESS (роутер вне пула)`.
- `ACTION_LABELS` — +4 lifecycle-действия (`activate`, `maintenance`, `maintenance_off`, `in_transit`).
- `LIFECYCLE_ACTIONS`, `READONLY_ACTIONS` — множества для гейта.
- `cb_action` — гейтит LIFECYCLE_ACTIONS до админа и роутит через kb_confirm.
- `_execute_action` — lifecycle-ветка в САМОМ начале, до offline-guard: `db.set_lifecycle(rid, status)` + audit + refresh `_show_router`.
- `_do_poll` — пропускает lifecycle-роутеры (`skip_lifecycle`), не меняет их online-флаг, не шлёт offline-алерты.
- `PAGE_SIZE=30`, `LIST_COLS=3`, `_owner_short_map(db, rids)` — single-SQL JOIN (bindings + clients).
- `_show_list` переписан: чипы-фильтры `online/offline/transit/maint/all` с счётчиками; 3 кнопки в ряд с `@owner4` или `×N`.
- `cb_list_search_stub` — плашка «поиск добавим в Stage 3»; dispatcher-случай добавлен ДО `data.startswith("list:")` (иначе split падает).
- `cb_vless_apply` — guard в начале: если `custom_vless_url` задан, перенаправить на «Вернуть в пул».
- **Custom VLESS flow** (A2):
  - `cb_vless_custom_start` → state `awaiting_custom_vless`.
  - text-handler `awaiting_custom_vless` → `validate_custom_vless` + `kb_confirm`.
  - `cb_vless_custom_confirm` → `do_set_vless` + `db.set_custom_vless` + audit `vless_custom_apply` (маскированный).
  - `cb_vless_pool_return` → `db.set_custom_vless(rid, None)` + audit `vless_custom_clear`.
- **WiFi flow** (клиент пкт 7):
  - `cb_wifi_menu` — читает live (или снапшот если offline).
  - `cb_wifi_show_password` — админ-only, явный пароль + audit `wifi_password_view`.
  - `cb_wifi_edit_start` → state `awaiting_wifi_ssid`.
  - text-handler `awaiting_wifi_ssid` → валидация 1–32 B → state `awaiting_wifi_pwd`.
  - text-handler `awaiting_wifi_pwd` → валидация 8–63 ASCII → `kb_confirm` с предупреждением.
  - `cb_wifi_edit_confirm` → rate-limit для клиента → `do_set_wifi` + `db.set_wifi_snapshot` + audit `wifi_change` с JSON без пароля.
- **Owners flow** (A9):
  - `cb_owners_list` — табличка владельцев + кнопки «➕ Добавить» / «✖ <имя>».
  - `cb_owner_add_start` → state `awaiting_owner_add`.
  - text-handler `awaiting_owner_add` → `db.client_by_username` или `db.get_client(tg_id)` → `db.bind` + audit `owner_add`.
  - `cb_owner_remove` → `db.unbind` + audit `owner_remove` → перерисовывает список.
- Dispatcher `cb_router_msgs` — добавлены префиксы:
  - `vless:custom:`, `vless:capply:`, `vless:pool:`
  - `wifi:menu:`, `wifi:show:`, `wifi:edit:`, `wifi:wapply:`
  - `own:list:`, `own:add:`, `own:rm:`

---

## Safety / обратная совместимость

- Старые клиентские БД без новых колонок — `_migrate` в `__init__` добавит их `ALTER TABLE`-ами. `UPSERT` во всех setter-ах использует `COALESCE(excluded.X, router_state.X)` — NULL-значения не затрут ранее накопленное.
- `sqlite3.Row` access везде в try/except (IndexError, KeyError) — если роутер ещё не поллился, доступ к `st["lifecycle_status"]` не упадёт.
- Audit-формат без паролей и без сырого VLESS. UUID/pbk маскируются до 4 последних символов. WiFi пишет только JSON `{ssid_before, ssid_after}`.
- Лимит 5 WiFi-смен/сутки — только клиенту. Админу без лимита (для поддержки). Ключ `rate_limits.wifi_change_per_day` в cfg — можно крутить без кода.
- Transit-роутеры: клиент их не видит в главном меню, но если у него уже открыта глубокая ссылка на такой роутер — вместо меню покажется плашка «пока не активирован администратором».
- Maintenance-роутеры: клиент видит плашку и не может менять WiFi/VLESS/перезагружать. Админу — всё доступно.
- Custom VLESS guard в `cb_vless_apply`: ротация пула не может случайно перетереть кастомный ключ. Админу показываем путь «🔁 Вернуть в пул» перед сменой.
- Lifecycle-переходы обрабатываются до SSH-проверки — можно поставить в транзит роутер, который физически ещё не подключен.

---

## Чего НЕ сделано (Stage 3)

- Клиент пкт 8 (настройки роутинга — domain/all modes, custom list).
- Клиент пкт 2 (отправка log-дампа админу кнопкой).
- A6 push-уведомления (смена статуса → сообщение админу).
- A7 audit-лог UI + retention policy.
- A8 новый формат Global test с детальным разбором цепочки.
- `cb_list_search_stub` — placeholder, в Stage 3 превратится в полноценный поиск по id/label/owner.

---

## Sanity-чек

- `python3 -m py_compile bot/r_bot.py bot/router.py bot/db.py` → **OK**.
- FSM-переходы: custom_vless, wifi_ssid→wifi_pwd, owner_add — все с очисткой `state/state_rid/pending_*` на выходе (успех или /cancel).
- Dispatcher: `list:search_stub` обрабатывается до `list:` (иначе упал бы `split(":")`).

---

## Что дальше

1. Просмотри [STAGE-2.diff](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/docs/STAGE-2.diff) — это дифф поверх Stage 1.
2. Если нужен объединённый Stage 1 + Stage 2 патч — скажи, соберу. Или коммит-за-коммитом.
3. Дай добро — закоммичу как один или два коммита (Stage 1 / Stage 2) и запушу в `origin/rework/stage-1` или создам `origin/rework/stage-2`. Как скажешь.
4. После мерджа — Stage 3 (пкт 8, пкт 2, A6–A8).
