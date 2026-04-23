#!/usr/bin/env bash
# restore.sh — восстановление r-bot из .tar.gz, сделанного backup.sh.
#
# Шаги:
#   1. Валидируем архив (есть MANIFEST.txt, есть var-lib/bot.db).
#   2. Останавливаем r-bot.
#   3. Делаем ПРЕДРЕСТОР-бэкап текущего состояния (на случай, если решишь откатить откат).
#   4. Раскладываем файлы из архива на своё место, с правильными правами.
#   5. Стартуем r-bot, ждём 5с, проверяем active.
#
# Использование:
#   sudo bash restore.sh /var/backups/r-bot/r-bot_2026-04-20_030001_daily.tar.gz

set -euo pipefail

ETC_DIR="${ETC_DIR:-/etc/r}"
VAR_DIR="${VAR_DIR:-/var/lib/r-bot}"
LOG_FILE="${LOG_FILE:-/var/log/r-bot.log}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/r-bot}"
SERVICE="${SERVICE:-r-bot.service}"

log()  { echo -e "\e[36m[restore]\e[0m $*"; }
warn() { echo -e "\e[33m[warn]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[fail]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускай под root"
[[ $# -ge 1 ]]    || die "использование: restore.sh <путь-к-бэкапу.tar.gz>"

ARC="$1"
[[ -f "${ARC}" ]] || die "файл не найден: ${ARC}"

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

log "распаковываю ${ARC}"
tar -xzf "${ARC}" -C "${TMP}"

[[ -f "${TMP}/MANIFEST.txt" ]] || die "архив не выглядит как r-bot backup (нет MANIFEST.txt)"

echo "─── MANIFEST ───"
cat "${TMP}/MANIFEST.txt"
echo "────────────────"

read -r -p "Восстановить из этого бэкапа? Текущее состояние будет перезаписано. [y/N]: " ans
[[ "${ans,,}" == "y" ]] || { log "отменено"; exit 0; }

# 1. Останавливаем сервис.
if systemctl is-active --quiet "${SERVICE}"; then
  log "останавливаю ${SERVICE}"
  systemctl stop "${SERVICE}"
fi

# 2. Предрестор-бэкап.
log "делаю предрестор-бэкап (на случай отката отката)"
bash "$(dirname "$0")/backup.sh" --tag pre-restore >/dev/null

# 3. Разворачиваем.
if [[ -d "${TMP}/etc-r" ]]; then
  mkdir -p "${ETC_DIR}"
  chmod 700 "${ETC_DIR}"
  for f in bot.yaml config.yaml; do
    if [[ -f "${TMP}/etc-r/${f}" ]]; then
      install -m 0600 -o root -g root "${TMP}/etc-r/${f}" "${ETC_DIR}/${f}"
      log "восстановлен ${ETC_DIR}/${f}"
    fi
  done
fi

if [[ -f "${TMP}/var-lib/bot.db" ]]; then
  mkdir -p "${VAR_DIR}"
  install -m 0600 -o root -g root "${TMP}/var-lib/bot.db" "${VAR_DIR}/bot.db"
  log "восстановлен ${VAR_DIR}/bot.db"
fi

# Лог НЕ перезаписываем (не хотим терять свежие строки), только дозаписываем маркер.
echo "=== restore from ${ARC} at $(date) ===" >> "${LOG_FILE}"

# 4. Старт.
log "systemctl start ${SERVICE}"
systemctl start "${SERVICE}"
sleep 5
if systemctl is-active --quiet "${SERVICE}"; then
  log "OK: ${SERVICE} active"
else
  warn "${SERVICE} не запустился — см. journalctl -u ${SERVICE} -n 100"
  exit 1
fi
