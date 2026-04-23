# r-bot

Telegram-бот для управления парком OpenWrt-роутеров через обратные SSH-туннели
`frps`. Работает поверх того же `/etc/r/config.yaml`, что и TUI-скрипт `r` —
оба инструмента делят один источник истины про ярлыки роутеров и диапазоны
портов.

Текущий парк: ~52 роутера, добавляются и меняются регулярно — админ редактирует
их прямо из бота или руками в YAML, бот подхватывает изменения без рестарта.

## Что умеет

- **Роли admin / client** с middleware. Клиент видит только свои idNN.
- **Привязка клиентов** тремя способами: вручную через `bot.yaml`,
  одноразовые invite-коды (`R07-XK9P`, 24 ч), заявки через `/request`.
- **Действия на роутере**: `ℹ info`, `🔄 podkop restart`, `✅ test (global check)`,
  `♻ reboot`, `📜 logread`, `📍 ping`, `🔗 VLESS из общего пула`.
- Любой деструктив — двойное подтверждение. Массовые (`Pall / Pfail / Rall`) —
  только admin, с подтверждением через ввод `YES`.
- **Фоновый polling** каждые 15 мин (настраивается). Обнаруживает упавшие
  роутеры и podkop=STOP; admin получает пуш.
- **Ежедневный digest** в 09:00 МСК — упавшие/поднявшиеся, состояние парка,
  активность клиентов.
- **Бэкапы**: ежедневный локальный (хранится 14 дней) + воскресный на Telegram
  админу архивом. Есть кнопка «💾 Бэкап сейчас» в настройках.
- **Обновление**: кнопка в боте «🔄 Обновить из Git» или `scripts/update.sh` по
  SSH — автобэкап, diff, rollback при падении после рестарта.
- **Логи**: `/var/log/r-bot.log` (ротация systemd/journald), runtime-тейлы
  прогонов — в `/var/lib/r-bot/runs/idNN/` (30 дней).
- **Rate-limits** для клиентов (reboot/podkop/vless — отдельные лимиты в сутки).

## Архитектура

```
Ubuntu server (с frps)
├── /opt/r-bot-src/            ← git clone этого репо
│   ├── bot/
│   │   ├── r_bot.py           ← Telegram-handlers + jobs
│   │   ├── router.py          ← SSH/Paramiko + VLESS UCI + discover
│   │   └── db.py              ← sqlite-слой (клиенты, пул, states, audit)
│   ├── scripts/install.sh update.sh backup.sh restore.sh preflight.sh
│   └── systemd/r-bot.service
├── /opt/r-bot-venv/           ← python venv (ставит install.sh)
├── /etc/r/
│   ├── bot.yaml               ← 600: token, admins, rate_limits, auto_update
│   └── config.yaml            ← 600: ssh.password, диапазоны портов, overrides
├── /var/lib/r-bot/
│   ├── bot.db                 ← sqlite
│   └── runs/idNN/*.log        ← полные тейлы global_check / logread
├── /var/log/r-bot.log
└── /var/backups/r-bot/        ← локальные .tar.gz
```

Бот подключается к роутерам по SSH через loopback `127.0.0.1:11XXX`, куда
`frps` уже пробросил туннели с роутеров (админ настраивает frps сам; бот
туда не лезет).

## Установка

Коротко:

```bash
git clone https://github.com/yarik88/r-bot /opt/r-bot-src
cd /opt/r-bot-src
sudo bash scripts/install.sh
sudo nano /etc/r/bot.yaml       # token, admins
sudo nano /etc/r/config.yaml    # ssh.password, overrides
sudo systemctl start r-bot
journalctl -u r-bot -f
```

Развёрнуто — в [`docs/INSTALL.md`](docs/INSTALL.md).

## Секретность

Репозиторий **публичный**, но в нём лежат только `*.example`-конфиги и код.
Настоящие `bot.yaml` / `config.yaml` находятся **только** в `/etc/r/` на
сервере, под `chmod 600 root:root`, и попадают в `.gitignore`.

Перед первым `git push` обязательно запусти `bash scripts/preflight.sh` —
он сканирует tracked-файлы на токены, пароли, VLESS-ссылки и публичные IP.

Подробнее — в [`docs/SECURITY.md`](docs/SECURITY.md).

## Команды Telegram

Клиент и admin:
- `/start` — показать главное меню (мои роутеры).
- `/help` — справка по кнопкам.
- `/cancel` — сбросить текущий диалог (например, ввод `YES`).
- `/code XXXX-YYYY` — активировать invite-код.
- `/request idNN` — оставить заявку админу на доступ к idNN.

Admin-only:
- Все команды клиента +
- Кнопки «⚙ Настройки» → добавить клиента, создать invite, одобрить заявку,
  добавить/редактировать/удалить роутер, наполнить VLESS-пул, запустить бэкап,
  обновить из Git.
- Массовые: `Pall` / `Pfail` / `Rall` с подтверждением словом `YES`.

## Обновление

```bash
sudo bash /opt/r-bot-src/scripts/update.sh
```

Или кнопкой в боте: `⚙ Настройки → 🔄 Обновить из Git`. Показывает diff,
спрашивает подтверждения, делает автобэкап, `git pull`, пересобирает venv
если менялся `requirements.txt`, рестартует сервис. При падении рестарта —
откатывает код на предыдущий коммит.

## Бэкап и восстановление

Бэкап (ручной):
```bash
sudo bash /opt/r-bot-src/scripts/backup.sh
```

Воскресный автобэкап в Telegram — настраивается в `bot.yaml.backup`:
```yaml
backup:
  weekly_telegram: true
  weekly_time: "10:00"
  weekly_day: "Sun"
  keep_days: 14
```

Восстановление:
```bash
sudo bash /opt/r-bot-src/scripts/restore.sh /var/backups/r-bot/r-bot_2026-04-20_*.tar.gz
```

Восстановит `/etc/r/bot.yaml`, `/etc/r/config.yaml`, `/var/lib/r-bot/bot.db`,
сделает предрестор-бэкап текущего состояния, стартанёт сервис, проверит
что поднялся.

## Лицензия

MIT, см. `LICENSE`.
