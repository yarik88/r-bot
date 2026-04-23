#!/usr/bin/env bash
# install.sh — установка/переустановка r-bot на сервере.
#
# Что делает:
#  1) ставит apt-зависимости (python3-venv, sqlite3, git, rsync);
#  2) создаёт venv в /opt/r-bot-venv, ставит в него pip-зависимости;
#  3) копирует код в /opt/r-bot-src (если запускается не оттуда);
#  4) разворачивает конфиги /etc/r/bot.yaml и /etc/r/config.yaml с правами 600
#     (если их ещё нет — из *.example; если есть — не трогает);
#  5) создаёт /var/lib/r-bot, /var/log/r-bot.log, /var/backups/r-bot;
#  6) ставит systemd unit, включает автозапуск;
#  7) НЕ стартует бота, пока ты не заполнил bot.yaml (токен/admins).
#
# Безопасно запускать повторно — идемпотентный.

set -euo pipefail

# ---- Пути (можно переопределить через env) ----
PREFIX_SRC="${PREFIX_SRC:-/opt/r-bot-src}"
PREFIX_VENV="${PREFIX_VENV:-/opt/r-bot-venv}"
ETC_DIR="${ETC_DIR:-/etc/r}"
VAR_DIR="${VAR_DIR:-/var/lib/r-bot}"
LOG_FILE="${LOG_FILE:-/var/log/r-bot.log}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/r-bot}"
SVC_UNIT="/etc/systemd/system/r-bot.service"

# ---- Guard ----
if [[ $EUID -ne 0 ]]; then
  echo "[install] запускай под root (sudo bash install.sh)" >&2
  exit 1
fi

log()  { echo -e "\e[36m[install]\e[0m $*"; }
warn() { echo -e "\e[33m[warn]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[fail]\e[0m $*" >&2; exit 1; }

# ---- Где лежит исходник, из которого запустили install.sh ----
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SELF_DIR}/.." && pwd)"
if [[ ! -f "${REPO_DIR}/bot/r_bot.py" ]]; then
  die "не нашёл bot/r_bot.py относительно ${REPO_DIR} — запускай из scripts/ внутри склонированного репо"
fi

# ---- 1. apt зависимости ----
log "apt update + install deps"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 python3-venv python3-pip \
    sqlite3 git rsync curl ca-certificates

# ---- 2. Код → /opt/r-bot-src ----
if [[ "${REPO_DIR}" != "${PREFIX_SRC}" ]]; then
  log "синхронизирую код в ${PREFIX_SRC}"
  mkdir -p "${PREFIX_SRC}"
  rsync -a --delete \
      --exclude '.git/' --exclude '__pycache__/' --exclude '*.pyc' \
      --exclude 'config/*.yaml' \
      "${REPO_DIR}/" "${PREFIX_SRC}/"
else
  log "код уже на месте (${PREFIX_SRC})"
fi
chown -R root:root "${PREFIX_SRC}"
chmod -R go-w "${PREFIX_SRC}"

# ---- 3. venv + pip ----
if [[ ! -x "${PREFIX_VENV}/bin/python" ]]; then
  log "создаю venv ${PREFIX_VENV}"
  python3 -m venv "${PREFIX_VENV}"
fi
log "обновляю pip и ставлю зависимости"
"${PREFIX_VENV}/bin/pip" install --quiet --upgrade pip
"${PREFIX_VENV}/bin/pip" install --quiet -r "${PREFIX_SRC}/requirements.txt"

# ---- 4. /etc/r ----
log "готовлю ${ETC_DIR}"
mkdir -p "${ETC_DIR}"
chmod 700 "${ETC_DIR}"
chown root:root "${ETC_DIR}"

if [[ ! -f "${ETC_DIR}/bot.yaml" ]]; then
  cp "${PREFIX_SRC}/config/bot.yaml.example" "${ETC_DIR}/bot.yaml"
  chmod 600 "${ETC_DIR}/bot.yaml"
  chown root:root "${ETC_DIR}/bot.yaml"
  warn "создан ${ETC_DIR}/bot.yaml из example — впиши token + admins ПЕРЕД стартом"
else
  log "${ETC_DIR}/bot.yaml уже существует — не трогаю"
  chmod 600 "${ETC_DIR}/bot.yaml"
fi

if [[ ! -f "${ETC_DIR}/config.yaml" ]]; then
  cp "${PREFIX_SRC}/config/config.yaml.example" "${ETC_DIR}/config.yaml"
  chmod 600 "${ETC_DIR}/config.yaml"
  chown root:root "${ETC_DIR}/config.yaml"
  warn "создан ${ETC_DIR}/config.yaml из example — впиши ssh.password"
else
  log "${ETC_DIR}/config.yaml уже существует — не трогаю"
  chmod 600 "${ETC_DIR}/config.yaml"
fi

# ---- 5. runtime-директории ----
log "создаю ${VAR_DIR}, ${BACKUP_DIR}, ${LOG_FILE}"
mkdir -p "${VAR_DIR}" "${VAR_DIR}/runs" "${BACKUP_DIR}"
chmod 700 "${VAR_DIR}" "${BACKUP_DIR}"
chown -R root:root "${VAR_DIR}" "${BACKUP_DIR}"

touch "${LOG_FILE}"
chmod 640 "${LOG_FILE}"
chown root:root "${LOG_FILE}"

# ---- 6. systemd ----
log "ставлю systemd unit → ${SVC_UNIT}"
install -m 0644 "${PREFIX_SRC}/systemd/r-bot.service" "${SVC_UNIT}"
systemctl daemon-reload
systemctl enable r-bot.service >/dev/null

# ---- 7. init db (безопасно — только создаст таблицы если их нет) ----
log "инициализация БД"
"${PREFIX_VENV}/bin/python" "${PREFIX_SRC}/bot/r_bot.py" --init-db --config "${ETC_DIR}/bot.yaml" \
  || warn "init-db упал (ожидаемо, если ты ещё не вписал token/admins) — запусти вручную после правки bot.yaml"

# ---- Финальные подсказки ----
cat <<EOF

────────────────────────────────────────────────────────────
УСТАНОВКА ЗАКОНЧЕНА — осталось 3 шага руками:

  1) открой ${ETC_DIR}/bot.yaml и впиши:
       token: "..."         (от @BotFather)
       admins: [твой_tg_id] (@userinfobot)

  2) открой ${ETC_DIR}/config.yaml и впиши:
       ssh.password: "..."  (root-пароль роутеров)

  3) проверь конфиг и запусти:
       ${PREFIX_VENV}/bin/python ${PREFIX_SRC}/bot/r_bot.py --init-db
       systemctl start r-bot
       journalctl -u r-bot -f        # или: tail -f ${LOG_FILE}

Обновление:  sudo bash ${PREFIX_SRC}/scripts/update.sh
Бэкап:       sudo bash ${PREFIX_SRC}/scripts/backup.sh
Восстан-ие:  sudo bash ${PREFIX_SRC}/scripts/restore.sh <файл.tar.gz>
────────────────────────────────────────────────────────────
EOF
