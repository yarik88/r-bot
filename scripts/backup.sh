#!/usr/bin/env bash
# backup.sh — локальный бэкап r-bot.
#
# Что кладёт в .tar.gz:
#   - /etc/r/bot.yaml       (токен + whitelist)
#   - /etc/r/config.yaml    (ssh-пароль + ярлыки роутеров)
#   - /var/lib/r-bot/bot.db (sqlite: клиенты, vless-пул, состояния, audit)
#   - /var/log/r-bot.log    (последние 10 MB — срезается head'ом)
#
# Не кладёт:
#   - /var/lib/r-bot/runs/  (локальные tail'ы прогонов — не критично)
#   - код (он в git)
#
# Ротация: старше keep_days (из bot.yaml.backup.keep_days, дефолт 14) — удаляются.
#
# Вызов:
#   sudo bash backup.sh                    # обычный бэкап с меткой времени
#   sudo bash backup.sh --tag pre-update   # с кастомным тегом для update.sh
#
# Cron'ом ставится из r_bot.py (job_backup_daily), этот скрипт — для ручных и update.sh.

set -euo pipefail

ETC_DIR="${ETC_DIR:-/etc/r}"
VAR_DIR="${VAR_DIR:-/var/lib/r-bot}"
LOG_FILE="${LOG_FILE:-/var/log/r-bot.log}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/r-bot}"
KEEP_DAYS="${KEEP_DAYS:-14}"

TAG="manual"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

log()  { echo -e "\e[36m[backup]\e[0m $*"; }
warn() { echo -e "\e[33m[warn]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[fail]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускай под root"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

TS=$(date +%Y-%m-%d_%H%M%S)
OUT="${BACKUP_DIR}/r-bot_${TS}_${TAG}.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

# 1. Копируем конфиги (конфиги в /etc/r — 600, сохраняем права через cp -a).
mkdir -p "${TMP}/etc-r"
[[ -f "${ETC_DIR}/bot.yaml" ]]    && cp -a "${ETC_DIR}/bot.yaml"    "${TMP}/etc-r/"
[[ -f "${ETC_DIR}/config.yaml" ]] && cp -a "${ETC_DIR}/config.yaml" "${TMP}/etc-r/"

# 2. Безопасный снимок sqlite (даже если бот сейчас пишет).
mkdir -p "${TMP}/var-lib"
if [[ -f "${VAR_DIR}/bot.db" ]]; then
  if command -v sqlite3 >/dev/null; then
    sqlite3 "${VAR_DIR}/bot.db" ".backup '${TMP}/var-lib/bot.db'"
  else
    warn "sqlite3 не установлен — копирую файл как есть (может быть неконсистентным)"
    cp -a "${VAR_DIR}/bot.db" "${TMP}/var-lib/bot.db"
  fi
fi

# 3. Хвост лога (не весь, чтоб не раздувать архив).
mkdir -p "${TMP}/var-log"
if [[ -f "${LOG_FILE}" ]]; then
  tail -c 10485760 "${LOG_FILE}" > "${TMP}/var-log/r-bot.log"  # 10 MB
fi

# 4. Манифест — удобно при restore разбираться что было.
{
  echo "r-bot backup"
  echo "timestamp: ${TS}"
  echo "tag: ${TAG}"
  echo "hostname: $(hostname)"
  echo "git_rev: $(cd /opt/r-bot-src 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo '?')"
  echo "---"
  (cd "${TMP}" && find . -type f -printf '%p  (%s bytes)\n')
} > "${TMP}/MANIFEST.txt"

# 5. Архив.
tar -czf "${OUT}" -C "${TMP}" .
chmod 600 "${OUT}"
chown root:root "${OUT}"

SIZE=$(du -h "${OUT}" | awk '{print $1}')
log "готово: ${OUT} (${SIZE})"

# 6. Ротация.
PRUNED=$(find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'r-bot_*.tar.gz' -mtime +${KEEP_DAYS} -print -delete | wc -l)
if [[ ${PRUNED} -gt 0 ]]; then
  log "удалено старых бэкапов (>${KEEP_DAYS}д): ${PRUNED}"
fi

# Вывод пути — чтобы update.sh/бот могли заюзать.
echo "${OUT}"
