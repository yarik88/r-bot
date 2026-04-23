#!/usr/bin/env bash
# update.sh — безопасное обновление r-bot из git.
#
# Делает: автобэкап → git fetch → показывает diff → ждёт Y → git pull →
# ставит зависимости если requirements.txt изменился → рестарт сервиса →
# ждёт 5 секунд и показывает статус. При любой ошибке — НЕ рестартует.
#
# Вызывается:
#   - руками в SSH (sudo bash /opt/r-bot-src/scripts/update.sh)
#   - из бота кнопкой "🔄 Обновить из Git" (бот запускает его же)
#   - cron'ом через auto_update в bot.yaml (флаг -y чтобы без подтверждения)

set -euo pipefail

PREFIX_SRC="${PREFIX_SRC:-/opt/r-bot-src}"
PREFIX_VENV="${PREFIX_VENV:-/opt/r-bot-venv}"
BRANCH="${BRANCH:-main}"
SERVICE="${SERVICE:-r-bot.service}"

YES=0
if [[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]]; then
  YES=1
fi

log()  { echo -e "\e[36m[update]\e[0m $*"; }
warn() { echo -e "\e[33m[warn]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[fail]\e[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускай под root"
[[ -d "${PREFIX_SRC}/.git" ]] || die "${PREFIX_SRC} не git-репо (клонируй из github)"

cd "${PREFIX_SRC}"

# 1. Автобэкап (малый — только БД и конфиг) перед обновлением.
log "автобэкап перед обновлением"
bash "${PREFIX_SRC}/scripts/backup.sh" --tag pre-update >/dev/null

# 2. Сохраняем чек-суммы чтобы понимать, менялся ли requirements.txt.
REQ_BEFORE=$(sha256sum requirements.txt 2>/dev/null | awk '{print $1}')
OLD_REV=$(git rev-parse --short HEAD)

# 3. Проверяем изменения в удалёнке.
log "git fetch origin ${BRANCH}"
git fetch --quiet origin "${BRANCH}"

NEW_REV=$(git rev-parse --short "origin/${BRANCH}")
if [[ "${OLD_REV}" == "${NEW_REV}" ]]; then
  log "уже на последней версии (${OLD_REV}), нечего делать"
  exit 0
fi

log "текущая:   ${OLD_REV}"
log "в remote:  ${NEW_REV}"
echo
echo "───── DIFF ─────"
git --no-pager log --oneline "HEAD..origin/${BRANCH}" | head -20
echo
git --no-pager diff --stat "HEAD..origin/${BRANCH}"
echo "────────────────"

# 4. Если локально есть изменения — паникуем, не хотим затереть правки руками.
if ! git diff-index --quiet HEAD --; then
  die "есть локальные незакоммиченные изменения (git status). Не обновляю."
fi

# 5. Подтверждение.
if [[ "${YES}" -ne 1 ]]; then
  read -r -p "Применить обновление и рестартовать бота? [y/N]: " ans
  [[ "${ans,,}" == "y" ]] || { log "отменено"; exit 0; }
fi

# 6. Pull.
log "git pull --ff-only"
git pull --ff-only --quiet origin "${BRANCH}"

# 7. requirements — ставим только если изменились.
REQ_AFTER=$(sha256sum requirements.txt 2>/dev/null | awk '{print $1}')
if [[ "${REQ_BEFORE}" != "${REQ_AFTER}" ]]; then
  log "requirements.txt поменялся — pip install"
  "${PREFIX_VENV}/bin/pip" install --quiet -r requirements.txt
else
  log "requirements.txt без изменений — pip не трогаю"
fi

# 8. Рестарт сервиса.
log "systemctl restart ${SERVICE}"
systemctl restart "${SERVICE}"

# 9. Проверка, что поднялся.
sleep 5
if systemctl is-active --quiet "${SERVICE}"; then
  log "OK: ${SERVICE} active (было ${OLD_REV}, стало ${NEW_REV})"
else
  warn "${SERVICE} не запустился после обновления! откатываю код."
  git reset --hard "${OLD_REV}"
  systemctl restart "${SERVICE}" || true
  die "откат выполнен, см. journalctl -u ${SERVICE} -n 100"
fi
