#!/usr/bin/env bash
# preflight.sh — параноидальная проверка ПЕРЕД первым git push в публичный репо.
#
# Запускай из корня репозитория:
#   bash scripts/preflight.sh
#
# Что проверяет:
#   1. .gitignore покрывает config/*.yaml (не .example), *.db, *.log, бэкапы.
#   2. В staged и tracked файлах НЕТ секретных паттернов:
#        - token: "..." (не пустой и не PASTE_YOUR...)
#        - password: "..." (не пустой и не PASTE...)
#        - vless://uuid@host... (живая VLESS-ссылка)
#        - bot-токены telegram вида 1234567890:ABCDEF...
#        - реальные IP-адреса серверов
#   3. Файлы /etc/r/*.yaml, *.db, *.log НЕ отслеживаются git'ом.
#   4. Бинарные *.db/*.tar.gz случайно не застейжены.
#
# Exit code ≠ 0 если нашёл хоть один flag — push блокируется автоматически.

set -uo pipefail

log()  { echo -e "\e[36m[preflight]\e[0m $*"; }
pass() { echo -e "\e[32m  ✓\e[0m $*"; }
flag() { echo -e "\e[31m  ✗\e[0m $*" >&2; ERR=$((ERR+1)); }
warn() { echo -e "\e[33m  !\e[0m $*" >&2; }

ERR=0

if [[ ! -d .git ]]; then
  echo "запускай из корня git-репо" >&2
  exit 2
fi

# ==== 1. .gitignore sanity ====
# Проверяем не текст .gitignore, а реальное поведение git-check-ignore —
# пофиг как оно записано ('bot.yaml' vs 'config/bot.yaml' vs '**/bot.yaml'),
# главное что файл игнорируется.
log "проверка .gitignore"
for path in 'config/bot.yaml' 'config/config.yaml' 'bot.db' '/var/log/r-bot.log' 'r-bot_2026-01-01.tar.gz'; do
  if git check-ignore -q "${path}" 2>/dev/null; then
    pass "git ignores ${path}"
  else
    flag "git НЕ игнорирует: ${path} — поправь .gitignore"
  fi
done

# ==== 2. Поиск секретных паттернов в tracked файлах ====
log "скан tracked-файлов на секреты"

# Соберём список файлов, которые git-отслеживает (не игнорирует).
FILES=$(git ls-files)

check_pattern() {
  local pattern="$1"
  local description="$2"
  # Берём только текстовые файлы, грепаем без учёта регистра, игнорим .example.
  local hits
  hits=$(echo "${FILES}" | grep -vE '\.example$|^LICENSE$|\.md$' | \
         xargs -d '\n' -I{} sh -c 'test -f "{}" && file -b "{}" | grep -q text && grep -HnIE "'"${pattern}"'" "{}" || true' 2>/dev/null || true)
  if [[ -n "${hits}" ]]; then
    flag "${description}:"
    echo "${hits}" | sed 's/^/      /' >&2
  else
    pass "${description} — чисто"
  fi
}

# Секретные паттерны — проверяем по одному.
check_pattern '(^|[^#])[[:space:]]*token:[[:space:]]*"[0-9]{6,}:[A-Za-z0-9_-]{30,}"' 'telegram bot token'
check_pattern '(^|[^#])[[:space:]]*password:[[:space:]]*"[^"]{4,}"' 'непустой password:'
check_pattern 'vless://[0-9a-f-]{30,}@' 'живая VLESS-ссылка'
check_pattern 'PASTE_(ROUTER_ROOT_PASSWORD|YOUR_BOT_TOKEN)_HERE' 'placeholder не заменён на пустоту (ок для .example, но не в .yaml)'

# Маски публичных IP — смотрим, не попали ли конкретные серверы.
# Разрешаем 127.0.0.1, 10./192.168./172.16-31 и public-примеры в .md.
IP_HITS=$(echo "${FILES}" | grep -vE '\.example$|\.md$|^LICENSE$' | \
    xargs -d '\n' grep -HnE '\b(178|94|91|188)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' 2>/dev/null || true)
if [[ -n "${IP_HITS}" ]]; then
  warn "нашёл IP-адреса (не обязательно секрет, но глянь глазами):"
  echo "${IP_HITS}" | sed 's/^/      /' >&2
else
  pass "публичные IP-адреса не найдены"
fi

# ==== 3. Опасные файлы случайно застейжены? ====
log "проверка staged (git diff --cached)"
STAGED=$(git diff --cached --name-only 2>/dev/null || true)
if [[ -n "${STAGED}" ]]; then
  for bad in 'config/bot.yaml' 'config/config.yaml'; do
    if echo "${STAGED}" | grep -qxF "${bad}"; then
      flag "застейжен ${bad} — НЕЛЬЗЯ коммитить, это с реальными секретами"
    fi
  done
  for ext in db log tar.gz; do
    if echo "${STAGED}" | grep -qE "\.${ext}\$"; then
      flag "в staged попал *.${ext} — не коммить бинарники и бэкапы"
    fi
  done
  pass "staged-сет проверен"
else
  pass "staged пуст (git add ничего не сделал — ок для dry-run)"
fi

# ==== 4. Пути /etc/r/... не должны попадать в tree вообще ====
if echo "${FILES}" | grep -qE '(^|/)etc/r/'; then
  flag "в tracked-файлах есть путь /etc/r/ — это быть не должно"
else
  pass "/etc/r/ не в repo"
fi

echo
if [[ ${ERR} -gt 0 ]]; then
  echo -e "\e[31mpreflight: найдено ${ERR} проблем(ы). git push ЗАБЛОКИРОВАН до фикса.\e[0m" >&2
  exit 1
else
  echo -e "\e[32mpreflight: чисто. можно делать git push.\e[0m"
  exit 0
fi
