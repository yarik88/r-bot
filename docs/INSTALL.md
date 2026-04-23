# Установка r-bot

Пошаговая инструкция. Сервер — Ubuntu 22.04+ с уже работающим `frps`.
Если frps не стоит, этот документ не поможет: бот не настраивает туннели,
только использует готовые.

## 0. Подготовка — что должно уже работать

На сервере проверь три вещи:

```bash
# 1. frps запущен и слушает 11XXX на loopback
ss -tlnp | awk '$4 ~ /127\.0\.0\.1:110[0-9][0-9]/ {print $4}' | sort -u
# должен выдать ~40+ строк вида 127.0.0.1:11007

# 2. roots роутеров достижимы по этим портам
ssh -p 11007 -o StrictHostKeyChecking=no root@127.0.0.1 'uci show podkop | head -3'
# должен подключиться, запросить пароль, выдать 3 строки подкопа

# 3. python3 >= 3.10
python3 --version
```

Если что-то из этого не работает — сначала чини frps/ключи, и только потом
ставь бота.

## 1. Клонируем репо

```bash
sudo git clone https://github.com/yarik88/r-bot /opt/r-bot-src
cd /opt/r-bot-src
```

Если уже клонировал и пришёл обновляться — см. `scripts/update.sh`.

## 2. Запускаем install.sh

```bash
sudo bash scripts/install.sh
```

Что сделает (всё идемпотентно, можно запускать повторно):

1. `apt install python3-venv sqlite3 git rsync curl` — если чего-то нет.
2. Синхронизирует `/opt/r-bot-src` (если запущен не оттуда) с текущего
   клона через `rsync`.
3. Создаёт `/opt/r-bot-venv`, ставит в него `-r requirements.txt`.
4. Если нет `/etc/r/bot.yaml` — кладёт из `config/bot.yaml.example` с
   правами 600 root:root. Если есть — не трогает.
5. То же для `/etc/r/config.yaml`.
6. Создаёт `/var/lib/r-bot`, `/var/backups/r-bot`, `/var/log/r-bot.log`.
7. Ставит systemd unit `r-bot.service`, делает `enable` (не старт).
8. Пытается инициализировать sqlite через `--init-db` (если токен/admins
   ещё не заполнены — ругнётся предупреждением, это нормально).

Финальное сообщение покажет что делать дальше.

## 3. Заполняем bot.yaml

```bash
sudo nano /etc/r/bot.yaml
```

Обязательные поля:

```yaml
token: "1234567890:AAH...."     # от @BotFather
admins:
  - 987654321                    # твой tg id от @userinfobot
```

Опционально — rate-limits и клиенты сразу вписать вместо invite-кодов:

```yaml
clients:
  123456789:
    role: client
    routers: [id07, id12]
    note: "Вася Петров"
```

Сохрани (`Ctrl+O`, `Enter`, `Ctrl+X`). Проверь:

```bash
sudo stat -c '%a %U:%G %n' /etc/r/bot.yaml
# 600 root:root /etc/r/bot.yaml
```

## 4. Заполняем config.yaml

```bash
sudo nano /etc/r/config.yaml
```

Обязательно:

```yaml
ssh:
  password: "РЕАЛЬНЫЙ_ПАРОЛЬ_РОУТЕРОВ"
```

Диапазоны `web_port_range` / `ssh_port_range` обычно подходят по умолчанию —
проверь, что совпадают с тем, что показывал `ss -tlnp` в шаге 0.

Секция `overrides` — ярлыки роутеров. Поначалу можно оставить пустой, бот
добавит дефолтные `idNN` сам. Позже через кнопку «✏ Редактировать ярлык»
или руками через `nano`:

```yaml
overrides:
  id01: "ASHOT"
  id02: "Dacha"
```

Проверь права:

```bash
sudo stat -c '%a %U:%G %n' /etc/r/config.yaml
```

## 5. Инициализация БД

```bash
sudo /opt/r-bot-venv/bin/python /opt/r-bot-src/bot/r_bot.py --init-db
```

Должно вывести что-то вроде:
```
БД инициализирована: /var/lib/r-bot/bot.db
Admin(s): [987654321]
```

Если ругается «bot.yaml не найден» или «token пустой» — вернись к шагу 3.

## 6. Первый запуск

Для отладки сначала в foreground:

```bash
sudo bash /opt/r-bot-src/scripts/r-bot-run.sh
```

Бот должен вывести `starting polling...` и зависнуть. Пиши ему `/start` в
Telegram с того аккаунта, чей id в `admins:`. Должно показаться главное
меню с списком твоих роутеров.

Если ок — `Ctrl+C`, запускай как сервис:

```bash
sudo systemctl start r-bot
sudo systemctl status r-bot
journalctl -u r-bot -f
```

## 7. Проверка бэкапа и автообновления

```bash
sudo bash /opt/r-bot-src/scripts/backup.sh
ls -la /var/backups/r-bot/
```

Должен появиться `r-bot_*.tar.gz` ~50 KB.

## 8. Первый push в публичный репо

**До** первого `git push` — обязательно:

```bash
cd /opt/r-bot-src        # или где у тебя локальный клон на твоей машине
bash scripts/preflight.sh
```

Если скрипт ругнулся (нашёл пароль/токен/vless:// в tracked-файлах) — **не пуш**,
сначала выясни где секрет просочился, убери, повтори preflight.

## Проблемы

| Симптом | Лечение |
|---|---|
| `ImportError: telegram` | `/opt/r-bot-venv/bin/pip install -r requirements.txt` |
| `AuthenticationException` на SSH | проверь `ssh.password` в `config.yaml`, попробуй вручную `ssh -p 11007 root@127.0.0.1` |
| Пустая таблица роутеров | `ss -tlnp | grep 127.0.0.1:110` должен выдать строки — если нет, `frps` не слушает на loopback, проверь `frps.toml` |
| `sudo` медленно стартует | `echo "127.0.1.1 $(hostname)" | sudo tee -a /etc/hosts` — косметика |
| Бот молчит на сообщения | user id не в `admins:` и не добавлен как client — сверь `@userinfobot` и `/etc/r/bot.yaml` |
| `job-queue: JobQueue не инициализирован` | ставь с `[job-queue]`: `/opt/r-bot-venv/bin/pip install 'python-telegram-bot[job-queue]'` |

## Откат установки

Если хочешь убрать бота полностью:

```bash
sudo systemctl disable --now r-bot
sudo rm -f /etc/systemd/system/r-bot.service
sudo systemctl daemon-reload

sudo rm -rf /opt/r-bot-src /opt/r-bot-venv
sudo rm -rf /var/lib/r-bot /var/log/r-bot.log
# /etc/r/ НЕ удаляем (им пользуется TUI-скрипт `r`)
# /var/backups/r-bot/ удаляй только если уверен, что бэкапы не нужны
```

`frps` при этом не трогается, его конфиг в `/opt/frps/frps.toml` остаётся.
