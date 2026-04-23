#!/usr/bin/env bash
# r-bot-run.sh — запуск бота в foreground под твоим venv.
#
# Использование:
#   sudo bash scripts/r-bot-run.sh              # --config /etc/r/bot.yaml по умолчанию
#   sudo bash scripts/r-bot-run.sh --init-db    # инициализировать БД
#
# systemd этим файлом НЕ пользуется (у него прямой ExecStart), этот скрипт —
# для отладки: видно логи в терминале, Ctrl+C мгновенно гасит бота.

set -euo pipefail
PREFIX_SRC="${PREFIX_SRC:-/opt/r-bot-src}"
PREFIX_VENV="${PREFIX_VENV:-/opt/r-bot-venv}"
exec "${PREFIX_VENV}/bin/python" -u "${PREFIX_SRC}/bot/r_bot.py" --config /etc/r/bot.yaml "$@"
