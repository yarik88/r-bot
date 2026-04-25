# Обновление r-bot до Stage 1+2+3 — максимально подробная инструкция

Цель: развернуть обновлённую версию r-bot на сервере `vm-78867` (IP `193.106.174.50`), сохранив полный бэкап старой рабочей версии, чтобы при проблеме откатиться **одной командой**.

Путь: **GitHub → `scripts/update.sh`**.
Время: 20–30 минут (с запасом).
Downtime бота: 10–30 сек (только рестарт).

---

## Где что лежит (карта файлов)

**На твоём Mac:**

- Локальный клон GitHub-репо — пусть будет `~/src/r-bot/` (если ещё нет — в шаге 1 склонируем).

**В Cowork (эта сессия):** обновлённые файлы лежат в `outputs/r-bot/bot-updated/`. Прямые ссылки — см. шаг 1.

**На сервере `vm-78867`:**

- **Код бота:** `/opt/r-bot-src/` — git-клон репы yarik88/r-bot
- **Python venv:** `/opt/r-bot-venv/` — виртуальное окружение (не трогаем)
- **База данных:** `/var/lib/r-bot/bot.db`
- **Конфиг бота:** `/etc/r/bot.yaml`
- **Конфиг роутеров:** `/etc/r/config.yaml`
- **Клиентские логи (Stage 3):** `/var/lib/r-bot/client_logs/` (создастся при первом использовании)
- **Бэкапы штатного backup.sh:** `/var/backups/r-bot/`
- **Лог бота:** `/var/log/r-bot.log`
- **Systemd unit:** `/etc/systemd/system/r-bot.service`
- **Наш мастер-бэкап и скрипт отката (создадим в шаге 3):** `/root/rollback-stage123/`

---

## Шаг 1. На Mac: подготовить код и запушить в GitHub

### 1.1. Скачать три обновлённых файла из Cowork

Кликни каждую ссылку — она сохранит файл на Mac (обычно в `~/Downloads/`):

- [db.py](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/bot-updated/db.py)
- [router.py](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/bot-updated/router.py)
- [r_bot.py](computer:///sessions/tender-focused-wright/mnt/outputs/r-bot/bot-updated/r_bot.py)

### 1.2. Проверить чексуммы скачанных файлов

Открой Terminal на Mac:

```bash
cd ~/Downloads
md5 db.py router.py r_bot.py
```

Должно вывести ровно эти суммы:

```
MD5 (db.py)     = 2f30a50ec47bac3f4d30ea5e4862adad
MD5 (router.py) = 884cd89c70be862a6999a925548c688e
MD5 (r_bot.py)  = 885f4912c2973fe7a1021ce6f56b9322
```

Если что-то не совпало — скачай заново.

### 1.3. Склонировать репу (если ещё нет) или подтянуть свежий main

```bash
# Если клона ещё нет:
mkdir -p ~/src
cd ~/src
git clone https://github.com/yarik88/r-bot
cd r-bot

# Если клон уже есть:
cd ~/src/r-bot
git checkout main
git pull --ff-only
```

Если на строке `git clone` или `git pull` спросит логин/пароль — введи свой GitHub-логин и **Personal Access Token** (не пароль от аккаунта — GitHub пароли для git-операций больше не принимает). Если токена нет — создай на https://github.com/settings/tokens → «Generate new token (classic)» → scope `repo`.

### 1.4. Подменить 3 файла в локальном клоне

```bash
cd ~/src/r-bot
cp ~/Downloads/db.py     bot/db.py
cp ~/Downloads/router.py bot/router.py
cp ~/Downloads/r_bot.py  bot/r_bot.py
```

### 1.5. Проверить что замена корректна

```bash
# MD5 внутри репы должен совпасть с эталоном:
md5 bot/db.py bot/router.py bot/r_bot.py

# Python-синтаксис валидный:
python3 -m py_compile bot/db.py bot/router.py bot/r_bot.py && echo "COMPILE OK"

# Что именно поменялось (ожидаем 3 файла, +~2000 / −10):
git status
git diff --stat
```

### 1.6. Закоммитить и запушить в GitHub

```bash
git add bot/db.py bot/router.py bot/r_bot.py

git commit -m "Stage 1+2+3: rework per REWORK-SPEC

- Stage 1: status model, podkop UX, region flags, global check
- Stage 2: WiFi, lifecycle, custom VLESS, filters, owners
- Stage 3: routing UI, send-log-to-admin, push notifications,
           audit UI + retention, new global test format"

git push origin main
```

Открой https://github.com/yarik88/r-bot в браузере и убедись, что коммит «Stage 1+2+3» появился в ветке `main`. Это точка невозврата этапа «GitHub» — код в удалёнке.

---

## Шаг 2. Зайти на сервер и проверить исходное состояние

```bash
ssh root@193.106.174.50
```

Сохранить текущую картину в переменные shell'а (пригодится для отката):

```bash
# Текущий git-хеш кода бота — то, к чему мы можем откатить git
OLD_GIT_REV=$(git -C /opt/r-bot-src rev-parse HEAD)
echo "OLD_GIT_REV=$OLD_GIT_REV"

# Проверяем, что бот сейчас жив
systemctl status r-bot --no-pager | head -15
# Ожидаемо: Active: active (running)
```

Если бот сейчас не running — **не продолжай**, сначала разберись почему.

---

## Шаг 3. Сделать мастер-бэкап + подготовить откат одной командой

Здесь мы делаем: 1) один tar-архив со всем содержимым бота, 2) shell-скрипт `rollback.sh`, который восстанавливает систему одной командой.

### 3.1. Создаём каталог для мастер-бэкапа

```bash
sudo mkdir -p /root/rollback-stage123
cd /root/rollback-stage123
```

### 3.2. Фиксируем старый git-хеш в файл (чтобы откат его знал)

```bash
sudo git -C /opt/r-bot-src rev-parse HEAD | sudo tee /root/rollback-stage123/OLD_GIT_REV
# Должно вывести тот же хеш что в переменной OLD_GIT_REV
```

### 3.3. Делаем «толстый» tar-архив со всем состоянием

```bash
sudo tar czf /root/rollback-stage123/full-backup.tgz \
     -C / \
     etc/r \
     var/lib/r-bot \
     var/log/r-bot.log \
     opt/r-bot-src/bot \
     2>/dev/null

ls -lh /root/rollback-stage123/full-backup.tgz
```

Должен получиться файл в диапазоне 1–50 МБ (зависит от размера БД и логов). В нём есть:

- `/etc/r/` — конфиги
- `/var/lib/r-bot/` — БД + все runs/ логи
- `/var/log/r-bot.log` — журнал
- `/opt/r-bot-src/bot/` — три python-файла до обновления

### 3.4. Создаём скрипт-откат одной командой

```bash
sudo tee /root/rollback-stage123/rollback.sh > /dev/null << 'ROLLBACK_EOF'
#!/usr/bin/env bash
# rollback.sh — ОТКАТ r-bot до состояния до Stage 1+2+3
# Запускать: sudo bash /root/rollback-stage123/rollback.sh
set -euo pipefail

SNAP=/root/rollback-stage123
OLD_REV=$(cat "${SNAP}/OLD_GIT_REV")

echo "[rollback] останавливаю r-bot"
systemctl stop r-bot || true

echo "[rollback] распаковываю master-backup в /"
tar xzf "${SNAP}/full-backup.tgz" -C /

echo "[rollback] откатываю git в /opt/r-bot-src к ${OLD_REV}"
cd /opt/r-bot-src
git reset --hard "${OLD_REV}" || true

echo "[rollback] запускаю r-bot"
systemctl start r-bot
sleep 3
systemctl status r-bot --no-pager | head -15

echo "[rollback] готово. проверь бота в Telegram."
ROLLBACK_EOF

sudo chmod +x /root/rollback-stage123/rollback.sh

ls -la /root/rollback-stage123/
```

Должны увидеть:

```
OLD_GIT_REV
full-backup.tgz
rollback.sh  (executable)
```

**ВАЖНО:** теперь откат = одна команда:

```bash
sudo bash /root/rollback-stage123/rollback.sh
```

Она остановит бота, распакует архив поверх `/` (вернёт код, БД, конфиг, логи) и запустит обратно.

### 3.5. Параллельно сделать штатный backup.sh (третья страховка)

```bash
sudo bash /opt/r-bot-src/scripts/backup.sh --tag pre-stage123
ls -lht /var/backups/r-bot/ | head -5
```

У нас теперь **три** независимых бэкапа:

1. GitHub хранит старую версию кода (хеш `$OLD_GIT_REV`)
2. `/root/rollback-stage123/full-backup.tgz` — полный snapshot + скрипт отката
3. `/var/backups/r-bot/r-bot-backup-pre-stage123-*.tgz` — штатный архив

---

## Шаг 4. Проверить что git видит новый коммит

```bash
cd /opt/r-bot-src
sudo git fetch origin main

# Покажет коммиты в удалёнке которых у нас ещё нет:
sudo git log --oneline HEAD..origin/main
```

Должны увидеть твой коммит «Stage 1+2+3: rework per REWORK-SPEC». Если пусто — значит пуш на шаге 1.6 не прошёл, возвращайся в Mac-терминал.

Проверяем что в /opt/r-bot-src/ нет «грязи» (иначе update.sh откажется работать):

```bash
sudo git -C /opt/r-bot-src status --short
# Ожидаемо: пусто
```

Если что-то есть — обычно это `__pycache__` или `.orig/.rej` файлы. Разберись с ними до следующего шага (убей `__pycache__`, если оно; `.rej` — подумай, что это).

---

## Шаг 5. Запустить обновление

```bash
sudo bash /opt/r-bot-src/scripts/update.sh
```

Скрипт сам:

1. Сделает свой автобэкап с тегом `pre-update`.
2. Покажет diff — ожидай что-то вроде:
   ```
   текущая:   abc1234
   в remote:  def5678
   ───── DIFF ─────
   def5678 Stage 1+2+3: rework per REWORK-SPEC
   
    bot/db.py     | 300+ ++-
    bot/router.py | 400+ ++-
    bot/r_bot.py  | 1500+ ++-
   ────────────────
   ```
3. Спросит:
   ```
   Применить обновление и рестартовать бота? [y/N]:
   ```
   Жми **y** и Enter.
4. Сделает `git pull --ff-only`.
5. Проверит `requirements.txt` — у нас не менялся, поэтому `pip install` пропустится.
6. `systemctl restart r-bot.service`.
7. Подождёт 5 секунд и проверит статус.
8. Если сервис не поднимется — автоматически `git reset --hard` до старой ревизии и рестарт старой версии.

Успешный финал:

```
[update] OK: r-bot.service active (было abc1234, стало def5678)
```

---

## Шаг 6. Проверка что бот живой

```bash
# Статус
systemctl status r-bot --no-pager | head -15

# Хеш кода
git -C /opt/r-bot-src rev-parse --short HEAD

# Хвост логов (дай боту минуту прогреться, потом посмотри)
sudo journalctl -u r-bot -n 60 --no-pager
```

В логе должны быть строки вроде:

```
r-bot v1.0 starting, config=/etc/r/bot.yaml
jobs: poll=15min, digest=09:00, backup_daily=03:00, auto_update=off
starting polling...
```

Чего быть **не должно**: `Traceback`, `ERROR`, бесконечных `OperationalError`.

Если увидишь Traceback — прыгай в **Шаг 8. Откат**.

---

## Шаг 7. Функциональная проверка в Telegram

**Админом:**

1. `/start` → в главном меню появились новые кнопки:
   - **🧪 Глобальный тест**
   - **📥 Логи от клиентов** (с счётчиком (0) если нет непрочитанных)
2. Открыть любой роутер (например, `id07`) → в его меню:
   - **📋 Маршрутизация** (всем)
   - **📜 Аудит роутера** (админу, рядом с «Info»)
3. Нажать **📜 Аудит роутера** → список записей с пагинацией → **📥 Экспорт CSV** → прилетел файл `audit_idNN.csv`.
4. Нажать **🧪 Глобальный тест** → бот сказал «запускаю на N роутерах» → через 30–120 сек прилетел файл `global_test_*.log` с PASS/WARN/FAIL в summary.

**Под клиентом** (если есть тестовый клиент или ты сам себя можешь переключить):

1. Открыть роутер → **📋 Маршрутизация** → **➕ Добавить** → прислать в чат:
   ```
   test.example
   ```
   → в ответе меню теперь говорит «Pending: ➕1» → нажать **✅ Применить** → секунд через 10 бот скажет «Маршрутизация обновлена».
   
   На роутере через SSH:
   ```bash
   ssh root@<роутер>
   uci show podkop.main.user_domains | grep test.example
   ```
   Должен найтись.

2. Вернуться в **📋 Маршрутизация** → **✏ Убрать** → ткнуть `test.example` → **✅ Применить** → исчез.

3. Нажать **▶️ Проверить** на карточке роутера → в ответе 3 кнопки, среди них новая: **📤 Отправить лог админу** → нажать → админу должен прилететь документ с логом и кнопками «👁 Прочитано» / «📜 Аудит роутера».

4. (Если будешь менять WiFi) — после успешной смены админу прилетит пуш «📶 idNN (@client): сменён WiFi …».

Ещё через сутки, после 04:15 UTC, в `journalctl -u r-bot` появятся:

```
audit retention: dropped N rows (>90 days)
client logs retention: db=N files=M (>30 days)
```

Это значит что retention-джобы Stage 3 работают.

---

## Шаг 8. Откат (если что-то пошло не так)

### Вариант 1 — «откат одной командой» (рекомендуется)

```bash
sudo bash /root/rollback-stage123/rollback.sh
```

Скрипт остановит бота, распакует master-backup поверх файловой системы, откатит git к старому хешу и запустит бота. В конце покажет `systemctl status`.

Проверь потом:

```bash
systemctl status r-bot --no-pager | head -10
git -C /opt/r-bot-src rev-parse --short HEAD
# Должен быть старый хеш
```

Всё, ты снова на рабочей версии до Stage 1+2+3.

### Вариант 2 — откат только кода (без БД), двумя командами

Если проблема только в коде, а БД не трогать (она совместима):

```bash
sudo git -C /opt/r-bot-src reset --hard $(cat /root/rollback-stage123/OLD_GIT_REV)
sudo systemctl restart r-bot
```

### Вариант 3 — штатный restore.sh (крайний случай)

Если по каким-то причинам `/root/rollback-stage123/` повреждён:

```bash
sudo bash /opt/r-bot-src/scripts/restore.sh \
    /var/backups/r-bot/r-bot-backup-pre-stage123-*.tgz
```

---

## Шаг 9. Когда всё ок — можно удалить мастер-бэкап (через неделю)

Не раньше чем через 5–7 дней уверенной работы новой версии (чтобы убедиться что всё реально ок):

```bash
sudo rm -rf /root/rollback-stage123
```

Штатные архивы в `/var/backups/r-bot/` бот сам ротирует по `cfg.backup.keep_days` — их не трогай.

---

## Итоговая шпаргалка

**Обновление:**

```bash
# На Mac:
cd ~/src/r-bot && cp ~/Downloads/{db,router,r_bot}.py bot/
git commit -am "Stage 1+2+3" && git push

# На VM:
ssh root@193.106.174.50
sudo mkdir -p /root/rollback-stage123
sudo git -C /opt/r-bot-src rev-parse HEAD | sudo tee /root/rollback-stage123/OLD_GIT_REV
sudo tar czf /root/rollback-stage123/full-backup.tgz -C / etc/r var/lib/r-bot var/log/r-bot.log opt/r-bot-src/bot 2>/dev/null
# (скопировать блок с rollback.sh из шага 3.4)
sudo bash /opt/r-bot-src/scripts/backup.sh --tag pre-stage123
sudo bash /opt/r-bot-src/scripts/update.sh
# Ответить y на вопрос о применении
```

**Откат одной командой:**

```bash
sudo bash /root/rollback-stage123/rollback.sh
```

**Проверка:**

```bash
systemctl status r-bot --no-pager | head -10
sudo journalctl -u r-bot -n 50 --no-pager
```

Удачи.
