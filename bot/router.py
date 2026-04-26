"""
router.py — всё про взаимодействие с роутерами OpenWrt через FRP.

Включает:
- discover() — по netstat находит онлайн-роутеры.
- Router — датакласс с id / ports / label.
- SSH — тонкий обёртка paramiko с таймаутами.
- Actions — info, reboot, podkop_restart, podkop_global_check, logs.
- VlessManager — UCI операции подкопа (чтение/запись proxy_string).
- cfg_edit_label — редактор YAML-оверрайдов (синхронизирован с `r`).
"""
from __future__ import annotations

import json
import re
import shlex
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import unquote, urlparse

import paramiko


# =============================================================================
# Discovery
# =============================================================================

@dataclass
class Router:
    id: str                 # "id07"
    web_port: int           # 10007
    ssh_port: int           # 11007
    label: str = ""         # имя владельца из config.yaml
    is_new: bool = False    # обнаружен, но нет записи в overrides

    @property
    def num(self) -> int:
        return int(self.id[2:])


def _parse_listening_ports() -> set[int]:
    """Парсим `ss -tlnH` (fallback на netstat -tln). Возвращаем множество портов
    на 127.0.0.1."""
    ports: set[int] = set()
    for cmd in (["ss", "-tlnH"], ["netstat", "-tln"]):
        try:
            out = subprocess.check_output(cmd, timeout=5, text=True, stderr=subprocess.DEVNULL)
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            # примерное: "LISTEN 0 128 127.0.0.1:10057 0.0.0.0:*"
            m = re.search(r"127\.0\.0\.1:(\d+)", line)
            if m:
                ports.add(int(m.group(1)))
        if ports:
            return ports
    return ports


def _format_router_id(num: int) -> str:
    """Variable-length: id01..id99 — 2-digit padding, id100..id999 — 3-digit.
    Сохраняет совместимость с существующими id07/id99 и расширяет до id999.
    Stage 1 / A4: max_routers=999."""
    return f"id{num:02d}" if num < 100 else f"id{num:03d}"


def discover(cfg: dict) -> list[Router]:
    """Возвращает список роутеров, онлайн-подключённых через FRPS."""
    web_lo, web_hi = cfg["web_port_range"]
    ssh_lo, ssh_hi = cfg["ssh_port_range"]
    overrides: dict = cfg.get("overrides") or {}

    ports = _parse_listening_ports()
    ssh_ports = [p for p in ports if ssh_lo <= p <= ssh_hi]
    routers: list[Router] = []
    seen_ids: set[str] = set()

    for p in sorted(ssh_ports):
        # num: 1..999, port - ssh_lo + 1.
        # Для ssh_lo=11001: port 11007 → num=7 → id07 (как раньше),
        # port 11100 → num=100 → id100 (раньше был баг id00 из-за p%100).
        num = p - ssh_lo + 1
        if num < 1 or num > 999:
            continue
        rid = _format_router_id(num)
        if rid in seen_ids:
            continue
        seen_ids.add(rid)
        web_port = web_lo + num
        label = overrides.get(rid, "") or ""
        is_new = rid not in overrides
        routers.append(Router(id=rid, web_port=web_port, ssh_port=p, label=label, is_new=is_new))

    return routers


def all_slots_from_config(cfg: dict) -> list[str]:
    """Возвращает все известные idNN из overrides (online + offline)."""
    overrides: dict = cfg.get("overrides") or {}
    return sorted(overrides.keys())


# =============================================================================
# SSH
# =============================================================================

class SSHError(Exception):
    pass


class SSH:
    """Тонкая обёртка paramiko с таймаутами. Контекст-менеджер."""

    def __init__(self, host: str, port: int, user: str, password: str, timeout: int = 8):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def __enter__(self) -> "SSH":
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except (paramiko.SSHException, socket.error, TimeoutError) as e:
            raise SSHError(f"connect {self.host}:{self.port}: {e}")
        return self

    def __exit__(self, *_):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None

    def run(self, cmd: str, timeout: int = 15) -> tuple[int, str, str]:
        assert self._client
        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except (paramiko.SSHException, socket.error, TimeoutError) as e:
            raise SSHError(f"run {cmd!r}: {e}")

    def run_ok(self, cmd: str, timeout: int = 15) -> str:
        rc, out, err = self.run(cmd, timeout=timeout)
        if rc != 0:
            raise SSHError(f"rc={rc} cmd={cmd!r} err={err.strip()}")
        return out


# =============================================================================
# Actions (что можно сделать с роутером)
# =============================================================================

#  Stage 1 / Пункт 1+3+A5: один комбинированный probe вместо нескольких
#  раундтрипов. Старая `/etc/init.d/podkop running` всегда возвращает
#  not-running т.к. подкоп не procd-демон — заменено на детектор по
#  процессу sing-box + nftables-таблице PodkopTable.
#  Дополнительно: LOCAL_IP (yandex.ru/internet идёт мимо VLESS),
#  EGRESS_JSON (ifconfig.co идёт через VLESS), MODEL/OPENWRT/PODKOPVER/
#  SINGBOXVER для админского info-экрана.
POLL_SCRIPT = r"""
echo "---UPTIME---"
cat /proc/uptime 2>/dev/null | awk '{print int($1)}' || echo 0
echo "---SING---"
pgrep -f "^/usr/bin/sing-box" >/dev/null 2>&1 && echo 1 || echo 0
echo "---TABLE---"
nft list tables 2>/dev/null | grep -q "PodkopTable" && echo 1 || echo 0
echo "---LOCAL---"
wget -qT5 -O- 'https://yandex.ru/internet/api/v0/ip/' 2>/dev/null | tr -d '"' | tr -d '\n'
echo ""
echo "---EGRESS---"
wget -qT5 -O- 'https://ifconfig.co/json' 2>/dev/null
echo ""
echo "---WAN---"
( ifstatus wan 2>/dev/null | awk -F'"' '/\"address\"/ {print $4; exit}' ) || echo ""
echo "---VLESS---"
uci -q get podkop.main.proxy_string || echo ""
echo "---MODEL---"
( cat /tmp/sysinfo/model 2>/dev/null ) \
 || ( ubus call system board 2>/dev/null | jsonfilter -e '@.model' 2>/dev/null ) \
 || echo ""
echo "---OPENWRT---"
( . /etc/openwrt_release 2>/dev/null && echo "$DISTRIB_RELEASE" ) || echo ""
echo "---PODKOPVER---"
opkg list-installed 2>/dev/null | awk '/^podkop /{print $3; exit}' || echo ""
echo "---SINGBOXVER---"
/usr/bin/sing-box version 2>/dev/null | awk '/sing-box version/{print $3; exit}' || echo ""
echo "---END---"
"""

# beta07 / B1: собственный сценарий global_check.
# Отказались от /usr/bin/podkop global_check, который давал ложные WARN
# (egress без фолбэков и парсер DNS не понимал FakeIP).
#
# Каждая строка вывода имеет префикс:
#   SING=0|1
#   TABLE=0|1
#   LOCAL=<wan-ip>
#   EGRESS=<ip>|<endpoint>      (первый успешный из 3 фолбэков, либо пусто)
#   DNS_SYS=<ip>                 (system resolver, может быть FakeIP 198.18.x)
#   DNS_88=<ip>                  (8.8.8.8, sanity-проверка UDP/53)
#   HTTP_YT=200|<other>|fail
#   HTTP_GOOGLE=200|<other>|fail
GLOBALCHECK_SCRIPT = r"""
SING=$(pgrep -f "^/usr/bin/sing-box" >/dev/null 2>&1 && echo 1 || echo 0)
TABLE=$(nft list tables 2>/dev/null | grep -q "PodkopTable" && echo 1 || echo 0)

LOCAL=$(uci -q get network.wan.ipaddr 2>/dev/null)
if [ -z "$LOCAL" ]; then
  LOCAL=$(ip -4 addr show 2>/dev/null \
            | awk '/inet /{ip=$2} END{split(ip,a,"/"); print a[1]}')
fi

EGRESS=""
EGRESS_VIA=""
for url in "https://api.ipify.org" "https://ifconfig.me" "https://ifconfig.co"; do
  raw=$(wget -qT8 -O- "$url" 2>/dev/null \
        | tr -d ' \r\n' \
        | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
        | head -1)
  if [ -n "$raw" ]; then
    EGRESS="$raw"
    EGRESS_VIA="$url"
    break
  fi
done

DNS_SYS=$(nslookup youtube.com 2>/dev/null \
          | awk '/^Address[: ]/ && NR>2 {print $NF; exit}' \
          | tr -d ' \r')
DNS_88=$(nslookup youtube.com 8.8.8.8 2>/dev/null \
         | awk '/^Address[: ]/ && NR>2 {print $NF; exit}' \
         | tr -d ' \r')

HTTP_YT=$(wget --spider -qT10 https://youtube.com 2>&1 \
          && echo 200 || echo fail)
HTTP_GOOGLE=$(wget --spider -qT10 https://www.google.com 2>&1 \
              && echo 200 || echo fail)

echo "SING=$SING"
echo "TABLE=$TABLE"
echo "LOCAL=$LOCAL"
echo "EGRESS=$EGRESS|$EGRESS_VIA"
echo "DNS_SYS=$DNS_SYS"
echo "DNS_88=$DNS_88"
echo "HTTP_YT=$HTTP_YT"
echo "HTTP_GOOGLE=$HTTP_GOOGLE"
"""

# Старые callsites могут ещё ссылаться на CHECK_CMD; оставим алиас для
# совместимости импортов (внутри файла он больше не используется).
CHECK_CMD = GLOBALCHECK_SCRIPT


def _format_uptime(seconds: int) -> str:
    if seconds <= 0:
        return "—"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d > 0:
        return f"{d}d {h:02d}:{m:02d}"
    return f"{h:02d}:{m:02d}"


def _section(out: str, name: str) -> str:
    """Достаёт кусок между ---NAME--- и следующим ---X--- маркером.
    Stage 1: расширили допустимые символы маркера на [A-Z_] чтобы поддержать
    PODKOPVER / SINGBOXVER (хотя сейчас уехали на бессуффиксные имена)."""
    m = re.search(rf"---{name}---\n?(.*?)(?=---[A-Z_]+---|\Z)", out, re.DOTALL)
    return m.group(1).strip() if m else ""


def _parse_egress_json(raw: str) -> dict:
    """ifconfig.co/json иногда добавляет посторонние строки (echo "" после
    wget). Достаём первый {...}-блок."""
    if not raw:
        return {}
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except (json.JSONDecodeError, ValueError):
        return {}


def _compute_podkop_status(sing: bool, table: bool, local_ip: str, egress_ip: str) -> str:
    """Stage 1: новый детектор статуса.
    - STOP: процесс sing-box не запущен или нет nftables-таблицы PodkopTable.
    - RUN: процесс есть, таблица есть, и трафик реально уходит через VLESS
      (egress_ip != local_ip).
    - BYPASS: процесс есть, но egress совпадает с local — трафик идёт мимо
      VLESS (например, маршруты слетели). Жёлтый предупреждающий статус.
    - RUN (без верификации): процесс есть, но один из IP-проб упал —
      даём benefit of the doubt.
    """
    if not sing or not table:
        return "STOP"
    if local_ip and egress_ip:
        return "RUN" if local_ip != egress_ip else "BYPASS"
    return "RUN"


@dataclass
class PollResult:
    online: bool = False
    uptime: str = "—"
    podkop: str = "UNKNOWN"   # legacy: RUN/STOP/BYPASS/UNKNOWN — для status_icon
    wan_ip: str = ""
    vless: str = ""
    error: str = ""
    # Stage 1 additions:
    sing_running: bool = False
    nft_table: bool = False
    local_ip: str = ""              # IP от провайдера (yandex)
    egress_ip: str = ""             # IP на выходе из VLESS (ifconfig.co)
    egress_country: str = ""        # full name e.g. "Germany"
    egress_country_iso: str = ""    # 2-letter ISO e.g. "DE"
    egress_city: str = ""
    egress_asn_org: str = ""
    podkop_via_vless: bool = False  # local_ip != egress_ip
    hw_model: str = ""
    openwrt_version: str = ""
    podkop_version: str = ""
    singbox_version: str = ""


def poll_router(r: Router, ssh_cfg: dict) -> PollResult:
    """Один роутер — быстрый опрос по SSH.
    Stage 1: один POLL_SCRIPT собирает все сигналы за один SSH-раундтрип."""
    try:
        with SSH(
            host=ssh_cfg.get("host", "127.0.0.1"),
            port=r.ssh_port,
            user=ssh_cfg.get("user", "root"),
            password=ssh_cfg["password"],
            timeout=ssh_cfg.get("connect_timeout", 8),
        ) as s:
            # Таймаут увеличен с 12 до 20 — два внешних wget'а могут занять
            # 5+5 секунд в худшем случае.
            _, out, _ = s.run(POLL_SCRIPT, timeout=20)

        # uptime
        upsec_str = (_section(out, "UPTIME") or "0").splitlines()[0].strip() or "0"
        try:
            upsec = int(upsec_str)
        except ValueError:
            upsec = 0

        # podkop signals
        sing = (_section(out, "SING") or "0").strip() == "1"
        table = (_section(out, "TABLE") or "0").strip() == "1"
        local_ip = (_section(out, "LOCAL") or "").strip()
        egress = _parse_egress_json(_section(out, "EGRESS"))
        egress_ip = (egress.get("ip") or "").strip()
        egress_country = (egress.get("country") or "").strip()
        egress_country_iso = (egress.get("country_iso") or "").strip()
        egress_city = (egress.get("city") or "").strip()
        egress_asn_org = (egress.get("asn_org") or "").strip()
        podkop_via_vless = bool(local_ip and egress_ip and local_ip != egress_ip)
        podkop_status = _compute_podkop_status(sing, table, local_ip, egress_ip)

        return PollResult(
            online=True,
            uptime=_format_uptime(upsec),
            podkop=podkop_status,
            wan_ip=_section(out, "WAN") or "",
            vless=_section(out, "VLESS") or "",
            sing_running=sing,
            nft_table=table,
            local_ip=local_ip,
            egress_ip=egress_ip,
            egress_country=egress_country,
            egress_country_iso=egress_country_iso,
            egress_city=egress_city,
            egress_asn_org=egress_asn_org,
            podkop_via_vless=podkop_via_vless,
            hw_model=(_section(out, "MODEL") or "").strip(),
            openwrt_version=(_section(out, "OPENWRT") or "").strip(),
            podkop_version=(_section(out, "PODKOPVER") or "").strip(),
            singbox_version=(_section(out, "SINGBOXVER") or "").strip(),
        )
    except SSHError as e:
        return PollResult(online=False, error=str(e))


def poll_all(routers: list[Router], ssh_cfg: dict, workers: int = 10) -> dict[str, PollResult]:
    """Параллельный опрос всех онлайн роутеров."""
    results: dict[str, PollResult] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(poll_router, r, ssh_cfg): r for r in routers}
        for f in futs:
            r = futs[f]
            try:
                results[r.id] = f.result(timeout=30)
            except Exception as e:
                results[r.id] = PollResult(online=False, error=str(e))
    return results


# --- конкретные действия ---

def do_reboot(r: Router, ssh_cfg: dict) -> tuple[bool, str]:
    """reboot — SSH рвётся, это нормально (rc=255 трактуем как успех)."""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run("reboot", timeout=5)
        # reboot рвёт соединение — rc может быть 0 или -1 или 255
        return True, "Команда reboot отправлена"
    except SSHError as e:
        msg = str(e).lower()
        if any(x in msg for x in ("closed", "timeout", "eof")):
            return True, "Соединение разорвано (ожидаемо при reboot)"
        return False, str(e)


def do_podkop_restart(r: Router, ssh_cfg: dict) -> tuple[bool, str]:
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run("service podkop restart 2>&1", timeout=30)
        ok = rc == 0
        msg = (out or err).strip() or "ok"
        return ok, msg
    except SSHError as e:
        return False, str(e)


def _classify_globalcheck(out: str) -> tuple[str, list[str], str]:
    """beta07 / B1: парсит вывод GLOBALCHECK_SCRIPT и формирует отчёт.

    Возвращает (verdict, report_lines, raw_out).
    verdict ∈ {'PASS','WARN','FAIL'}.

      FAIL — sing-box процесс не запущен ИЛИ нет PodkopTable.
      WARN — оба компонента работают, но есть деградация:
             egress не получен, DNS системный мёртв, HTTP-проба упала,
             egress совпадает с local (трафик мимо VLESS).
      PASS — всё чисто.
    """
    sing = False
    table = False
    local_ip = ""
    egress_ip = ""
    egress_via = ""
    dns_sys = ""
    dns_88 = ""
    http_yt = ""
    http_google = ""

    for ln in (out or "").splitlines():
        ln = ln.rstrip()
        if ln.startswith("SING="):
            sing = ln.endswith("=1")
        elif ln.startswith("TABLE="):
            table = ln.endswith("=1")
        elif ln.startswith("LOCAL="):
            local_ip = ln[len("LOCAL="):].strip()
        elif ln.startswith("EGRESS="):
            raw = ln[len("EGRESS="):]
            ip_part, _, via_part = raw.partition("|")
            egress_ip = ip_part.strip()
            egress_via = via_part.strip()
        elif ln.startswith("DNS_SYS="):
            dns_sys = ln[len("DNS_SYS="):].strip()
        elif ln.startswith("DNS_88="):
            dns_88 = ln[len("DNS_88="):].strip()
        elif ln.startswith("HTTP_YT="):
            http_yt = ln[len("HTTP_YT="):].strip()
        elif ln.startswith("HTTP_GOOGLE="):
            http_google = ln[len("HTTP_GOOGLE="):].strip()

    lines: list[str] = []

    # 1. sing-box
    lines.append(
        f"[{'OK' if sing else 'FAIL'}] sing-box процесс "
        f"{'жив' if sing else 'НЕ найден'}"
    )
    # 2. nftables
    lines.append(
        f"[{'OK' if table else 'FAIL'}] PodkopTable в nftables "
        f"{'найдена' if table else 'НЕ найдена'}"
    )
    # 3. local_ip
    if local_ip:
        lines.append(f"[OK] local_ip: {local_ip}")
    else:
        lines.append("[WARN] local_ip: не получен (uci/ip не вернули WAN адрес)")
    # 4. egress_ip с указанием эндпоинта
    if egress_ip:
        via_extra = f" (via {egress_via})" if egress_via else ""
        lines.append(f"[OK] egress_ip: {egress_ip}{via_extra}")
    else:
        lines.append(
            "[WARN] egress_ip: ни один из 3 эндпоинтов "
            "(api.ipify.org, ifconfig.me, ifconfig.co) не ответил за 8с — "
            "возможна блокировка исходящего"
        )
    # 5. egress vs local
    if egress_ip and local_ip:
        if egress_ip == local_ip:
            lines.append(
                "[WARN] egress == local → подкоп НЕ перенаправляет трафик "
                "(маршруты сломаны или sing-box не активен)"
            )
        else:
            lines.append("[OK] egress ≠ local → трафик идёт через VLESS")
    else:
        # Уже отметили выше отдельными WARN; не дублируем как WARN сравнения.
        lines.append(
            "[INFO] сравнение egress/local пропущено (нет одного из значений)"
        )
    # 6. DNS via system — FakeIP считается как OK
    if dns_sys:
        if dns_sys.startswith("198.18.") or dns_sys.startswith("198.19."):
            lines.append(
                f"[OK] DNS via system: youtube.com={dns_sys} "
                "(via fakeip → подкоп)"
            )
        else:
            lines.append(f"[OK] DNS via system: youtube.com={dns_sys}")
    else:
        lines.append("[WARN] DNS via system: нет ответа от 127.0.0.1:53")
    # 7. DNS via 8.8.8.8 — sanity (если нет — UDP/53 заблокирован, не critical)
    if dns_88:
        lines.append(f"[OK] DNS via 8.8.8.8: youtube.com={dns_88}")
    else:
        lines.append(
            "[WARN] DNS via 8.8.8.8: нет ответа (UDP/53 заблокирован?)"
        )
    # 8. HTTP youtube
    if http_yt == "200":
        lines.append("[OK] curl https://youtube.com → 200 OK")
    else:
        lines.append(
            f"[WARN] curl https://youtube.com → "
            f"{http_yt or 'нет ответа'}"
        )
    # 9. HTTP google
    if http_google == "200":
        lines.append("[OK] curl https://www.google.com → 200 OK")
    else:
        lines.append(
            f"[WARN] curl https://www.google.com → "
            f"{http_google or 'нет ответа'}"
        )

    # Вердикт
    if not sing or not table:
        verdict = "FAIL"
    elif any(ln.startswith("[WARN]") or ln.startswith("[FAIL]")
             for ln in lines):
        verdict = "WARN"
    else:
        verdict = "PASS"

    return verdict, lines, out or ""


def do_global_check(r: Router, ssh_cfg: dict) -> tuple[str, list[str], str]:
    """beta07 / B1: переписанный global_check.

    Запускает GLOBALCHECK_SCRIPT (собственный bash, не зависит от
    /usr/bin/podkop global_check) и возвращает (verdict, lines, full).

    Контракт изменён по сравнению с beta06:
        OLD: (bool ok, str full, str raw)  — тот же `full` дважды,
             ok классифицировался поиском подстрок «error»/«fail» в lower(full).
        NEW: (str verdict, list[str] lines, str raw)
             verdict ∈ {'PASS','WARN','FAIL'}.

    Вызывающий код в _execute_action / r_bot.py обновлён.
    """
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, err = s.run(GLOBALCHECK_SCRIPT, timeout=60)
    except SSHError as e:
        return "FAIL", [f"[FAIL] SSH: {e}"], str(e)

    raw = (out or "")
    if err and err.strip():
        raw += "\n--- stderr ---\n" + err
    return _classify_globalcheck(raw)


def do_info(r: Router, ssh_cfg: dict) -> str:
    """Короткий info: uptime, память, podkop status, podkop profile."""
    script = r"""
echo "## uptime"
uptime
echo ""
echo "## memory"
free -h | head -n 2
echo ""
echo "## podkop status"
service podkop status 2>&1 | head -n 10 || true
echo ""
echo "## podkop profile (uci)"
uci show podkop 2>/dev/null | head -n 30 || echo "uci podkop not set"
"""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, err = s.run(script, timeout=15)
        return out or err or "(empty)"
    except SSHError as e:
        return f"SSH error: {e}"


def do_logread(r: Router, ssh_cfg: dict, lines: int = 50) -> str:
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, _ = s.run(f"logread | tail -n {lines}", timeout=15)
        return out or "(empty)"
    except SSHError as e:
        return f"SSH error: {e}"


def do_podkop_logs(r: Router, ssh_cfg: dict, lines: int = 50) -> str:
    script = f"logread 2>/dev/null | grep -i podkop | tail -n {lines}"
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, _ = s.run(script, timeout=15)
        return out or "(нет записей podkop в логе)"
    except SSHError as e:
        return f"SSH error: {e}"


def do_ping(r: Router, ssh_cfg: dict, target: str, count: int = 4) -> str:
    # защита от shell-injection — пропускаем через shlex.quote
    target_q = shlex.quote(target)
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, err = s.run(f"ping -c {count} -W 2 {target_q}", timeout=15)
        return (out or err).strip() or "(empty)"
    except SSHError as e:
        return f"SSH error: {e}"


# =============================================================================
# VLESS UCI management
# =============================================================================

_VLESS_RE = re.compile(r"^vless://[A-Za-z0-9\-]+@[^\s]+$")


def parse_vless(url: str) -> tuple[str, str]:
    """Разобрать vless:// на (remark, host). Если remark нет — использовать host."""
    url = url.strip()
    # remark = фрагмент после #
    if "#" in url:
        base, frag = url.rsplit("#", 1)
        remark = unquote(frag).strip()
    else:
        base, remark = url, ""
    # host из URL (между @ и :)
    try:
        # urlparse не знает vless, но схожо с ws://... — парсим вручную
        parsed = urlparse(base.replace("vless://", "http://", 1))
        host = parsed.hostname or ""
    except Exception:
        host = ""
    if not remark:
        remark = host or "(без имени)"
    return remark, host


def do_set_vless(r: Router, ssh_cfg: dict, vless_url: str, restart: bool = True) -> tuple[bool, str]:
    """Пишет proxy_string в UCI и рестартует подкоп."""
    url_q = shlex.quote(vless_url)
    script = f"""
uci set podkop.main.proxy_string={url_q}
uci commit podkop
{'service podkop restart 2>&1' if restart else 'echo "(no restart)"'}
"""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=45)
        ok = rc == 0
        return ok, (out or err).strip() or "ok"
    except SSHError as e:
        return False, str(e)


def do_get_vless(r: Router, ssh_cfg: dict) -> str:
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, _ = s.run("uci -q get podkop.main.proxy_string", timeout=10)
        return (out or "").strip()
    except SSHError as e:
        return ""


# =============================================================================
# Stage 2 / A2: строгая валидация custom VLESS
# =============================================================================

# Минимальный набор обязательных query-параметров для reality-VLESS:
#   security=reality, pbk=<...>, sni=<...>
# fp/sid/type — опциональны, не валидируем.

_VLESS_RE = re.compile(
    r"^vless://([0-9a-fA-F-]{32,40})@([A-Za-z0-9.\-]+):(\d{1,5})\?(.+?)(#.*)?$"
)


def validate_custom_vless(url: str) -> tuple[bool, str, dict]:
    """Возвращает (ok, error_or_short, parsed_fields).
    parsed_fields: {id, host, port, security, pbk, sni}.
    short = укороченный вид для подтверждения, например
    'vless://…@de.example.com:443/...'."""
    if not url or not isinstance(url, str):
        return False, "пустой URL", {}
    url = url.strip()
    if not url.startswith("vless://"):
        return False, "должен начинаться с vless://", {}
    m = _VLESS_RE.match(url)
    if not m:
        return False, "не удалось распарсить vless URL", {}
    uuid, host, port_s, query, _frag = m.groups()
    try:
        port = int(port_s)
    except ValueError:
        return False, "порт не число", {}
    if not (1 <= port <= 65535):
        return False, "порт вне диапазона 1..65535", {}
    # Парсим query вручную (urlparse не дружит с vless)
    params: dict[str, str] = {}
    for kv in query.split("&"):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        params[k.strip()] = v.strip()
    if params.get("security", "").lower() != "reality":
        return False, "поддерживается только security=reality", {}
    if not params.get("pbk"):
        return False, "отсутствует pbk", {}
    if not params.get("sni"):
        return False, "отсутствует sni", {}
    short = f"vless://…@{host}:{port}/?security=reality&sni={params['sni']}"
    return True, short, {
        "id": uuid,
        "host": host,
        "port": port,
        "security": "reality",
        "pbk": params["pbk"],
        "sni": params["sni"],
    }


def mask_vless_for_audit(url: str) -> str:
    """Маскирует чувствительные поля для записи в audit:
    UUID и pbk — оставляем последние 4 символа, остальное → ***."""
    def _mask(s: str) -> str:
        if not s or len(s) <= 4:
            return "***"
        return "***" + s[-4:]
    try:
        m = _VLESS_RE.match(url.strip())
        if not m:
            return "vless://(invalid)"
        uuid, host, port_s, query, _frag = m.groups()
        new_q_parts = []
        for kv in query.split("&"):
            if "=" not in kv:
                new_q_parts.append(kv)
                continue
            k, v = kv.split("=", 1)
            if k == "pbk":
                new_q_parts.append(f"pbk={_mask(v)}")
            else:
                new_q_parts.append(kv)
        return f"vless://{_mask(uuid)}@{host}:{port_s}?{'&'.join(new_q_parts)}"
    except Exception:
        return "vless://(masked)"


# =============================================================================
# Stage 2 / клиентский пункт 7: WiFi read / apply
# =============================================================================

# Скрипт для чтения текущих SSID/encryption на обоих радио (2.4 + 5).
# Парсим вывод uci через простой grep — busybox awk бывает капризный.
WIFI_READ_SCRIPT = r"""
echo "===SSID0==="
uci -q get wireless.@wifi-iface[0].ssid
echo "===KEY0==="
uci -q get wireless.@wifi-iface[0].key
echo "===ENC0==="
uci -q get wireless.@wifi-iface[0].encryption
echo "===SSID1==="
uci -q get wireless.@wifi-iface[1].ssid
echo "===KEY1==="
uci -q get wireless.@wifi-iface[1].key
echo "===ENC1==="
uci -q get wireless.@wifi-iface[1].encryption
echo "===END==="
"""


@dataclass
class WifiInfo:
    ssid: str = ""
    key: str = ""
    encryption: str = ""
    # Если 2.4 и 5 ГГц расходятся (наследие до объединения) — фиксируем.
    consistent: bool = True
    note: str = ""
    error: str = ""


def _wifi_section(out: str, name: str) -> str:
    pat = re.compile(rf"===\s*{re.escape(name)}\s*===\n([\s\S]*?)(?=\n===|\Z)")
    m = pat.search(out)
    if not m:
        return ""
    return m.group(1).strip()


def do_get_wifi(r: Router, ssh_cfg: dict) -> WifiInfo:
    """Читает текущие WiFi-настройки. Если 2.4 и 5 ГГц настроены по-разному —
    возвращает значения от iface[0] и note='radios out of sync'."""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, _ = s.run(WIFI_READ_SCRIPT, timeout=15)
    except SSHError as e:
        return WifiInfo(error=str(e))
    s0 = _wifi_section(out, "SSID0")
    s1 = _wifi_section(out, "SSID1")
    k0 = _wifi_section(out, "KEY0")
    k1 = _wifi_section(out, "KEY1")
    e0 = _wifi_section(out, "ENC0")
    e1 = _wifi_section(out, "ENC1")
    consistent = (s0 == s1) and (k0 == k1) and (e0 == e1)
    note = "" if consistent else "2.4 и 5 ГГц настроены по-разному, бот применит общий профиль на оба радио"
    return WifiInfo(
        ssid=s0,
        key=k0,
        encryption=e0,
        consistent=consistent,
        note=note,
    )


def do_set_wifi(r: Router, ssh_cfg: dict, ssid: str, password: str) -> tuple[bool, str]:
    """Применяет общие SSID/password на wifi-iface[0] и [1] с шифрованием psk2.
    После uci commit — `wifi reload` (НЕ перезагружает роутер, только радио)."""
    if not (1 <= len(ssid.encode("utf-8")) <= 32):
        return False, "SSID должен быть 1-32 байта"
    if not (8 <= len(password) <= 63):
        return False, "пароль должен быть 8-63 символа"
    if not all(32 <= ord(c) < 127 for c in password):
        return False, "пароль должен содержать только печатные ASCII"
    ssid_q = shlex.quote(ssid)
    pwd_q = shlex.quote(password)
    script = f"""
uci set wireless.@wifi-iface[0].ssid={ssid_q}
uci set wireless.@wifi-iface[0].key={pwd_q}
uci set wireless.@wifi-iface[0].encryption='psk2'
uci set wireless.@wifi-iface[1].ssid={ssid_q} 2>/dev/null || true
uci set wireless.@wifi-iface[1].key={pwd_q} 2>/dev/null || true
uci set wireless.@wifi-iface[1].encryption='psk2' 2>/dev/null || true
uci commit wireless
wifi reload 2>&1 || /sbin/wifi reload 2>&1
echo "(wifi reload done)"
"""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=30)
        ok = rc == 0
        return ok, (out or err).strip() or "ok"
    except SSHError as e:
        return False, str(e)


# =============================================================================
# Stage 3 / Клиент пкт 8: Custom routing (list user_domains)
# =============================================================================
#
# Подкоп хранит список доменов в uci ключе `podkop.main.user_domains` (add_list).
# Переключатель `user_domain_list_type` определяет, активен ли список:
#   - 'dynamic' — список используется
#   - 'disabled' — игнорируется (пустой список)
#
# Наш UI:
#   - читаем текущий список через `uci -q get podkop.main.user_domains`
#     (возвращается одна строка со всеми элементами через пробел, если uci list)
#   - показываем клиенту, он правит в буфере (таблица pending_routing)
#   - при Apply: del_list, add_list, auto user_domain_list_type, commit, restart

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def validate_domain(d: str) -> tuple[bool, str]:
    """True / (False, reason). Строгая валидация по spec пкт 8."""
    if not d:
        return False, "пусто"
    if len(d) > 253:
        return False, "слишком длинный (>253)"
    if not _DOMAIN_RE.match(d):
        return False, "не похож на домен"
    return True, ""


def do_get_routing(r: Router, ssh_cfg: dict) -> tuple[bool, list[str], str]:
    """Читает podkop.main.user_domains. Возвращает (ok, list, error_msg).
    Порядок доменов сохраняется как в uci (добавление в конец)."""
    # uci show podkop | grep user_domains — даёт все add_list элементы по одной
    # строке:   podkop.main.user_domains='example.com'
    script = (
        "uci -q show podkop.main.user_domains 2>/dev/null || true\n"
        "uci -q get podkop.main.user_domain_list_type 2>/dev/null || echo __NONE__\n"
    )
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=15)
    except SSHError as e:
        return False, [], str(e)
    domains: list[str] = []
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # podkop.main.user_domains='example.com' или podkop.main.user_domains=example.com
        m = re.match(r"^podkop\.main\.user_domains=['\"]?([^'\"]+)['\"]?\s*$", ln)
        if m:
            val = m.group(1).strip()
            if val:
                domains.append(val)
    return True, domains, ""


def do_set_routing(
    r: Router,
    ssh_cfg: dict,
    to_add: list[str],
    to_remove: list[str],
) -> tuple[bool, str]:
    """Применить diff: del_list removed + add_list added, переключить
    user_domain_list_type по итоговому размеру, commit + podkop restart.

    Возвращает (ok, message). to_add/to_remove должны быть провалидированы
    снаружи (validate_domain)."""
    # Защита от инъекций: все значения прогоняем через validate + shlex.quote.
    for d in to_add + to_remove:
        ok, why = validate_domain(d)
        if not ok:
            return False, f"invalid domain '{d}': {why}"

    lines: list[str] = []
    # Удаления
    for d in to_remove:
        lines.append(f"uci del_list podkop.main.user_domains={shlex.quote(d)} 2>/dev/null || true")
    # Добавления
    for d in to_add:
        lines.append(f"uci add_list podkop.main.user_domains={shlex.quote(d)}")
    # Итоговый размер и переключатель user_domain_list_type
    lines.append(
        "REMAINING=$(uci -q get podkop.main.user_domains 2>/dev/null | wc -w)"
    )
    lines.append('if [ "$REMAINING" -gt 0 ]; then')
    lines.append("  uci set podkop.main.user_domain_list_type='dynamic'")
    lines.append("else")
    lines.append("  uci set podkop.main.user_domain_list_type='disabled'")
    lines.append("fi")
    lines.append("uci commit podkop")
    lines.append("/etc/init.d/podkop restart 2>&1 || true")
    lines.append('echo "(routing applied)"')
    script = "\n".join(lines)
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=45)
        if rc != 0:
            return False, (err or out).strip() or f"exit={rc}"
        return True, (out or "ok").strip()
    except SSHError as e:
        return False, str(e)


# =============================================================================
# Stage 3 / Клиент пкт 2: capture log-дамп для отправки админу.
# =============================================================================

# =============================================================================
# beta07 / F5: Speedtest — двухканальный замер (intl + RU)
# =============================================================================
# Стратегия:
#   intl  — Cloudflare 100MB через подкоп (https://speed.cloudflare.com/__down)
#   RU    — mirror.yandex.ru/archlinux ISO напрямую (без подкопа маршрута)
# Каждый бенч: одна команда `curl -m 30 -w "%{speed_download} %{time_total}
# %{http_code}"`. Пинг — `ping -c 5 -W 2 <host>`, парсим средний RTT.
# Полный таймаут на роутере: ≈ 80 секунд (30+30+ping+overhead).

SPEEDTEST_SCRIPT = r"""
TIMEOUT=30
INTL_URL="https://speed.cloudflare.com/__down?bytes=104857600"
RU_URL="https://mirror.yandex.ru/archlinux/iso/latest/archlinux-x86_64.iso"

# Helper: усреднённый RTT из вывода `ping`. Поле 5 в строке /min/avg/max/...
ping_avg () {
    ping -c 5 -W 2 "$1" 2>/dev/null \
        | awk -F'/' '/^rtt|^round-trip/ {print $5}' \
        | head -n 1
}

# === INTL ===
INTL_RAW=$(curl -o /dev/null -s -m $TIMEOUT \
    -w "%{speed_download} %{time_total} %{http_code}" \
    "$INTL_URL" 2>/dev/null)
INTL_BPS=$(echo "$INTL_RAW"  | awk '{print $1+0}')
INTL_TIME=$(echo "$INTL_RAW" | awk '{print $2+0}')
INTL_HTTP=$(echo "$INTL_RAW" | awk '{print $3+0}')
INTL_MBPS=$(awk -v b="$INTL_BPS" 'BEGIN{printf "%.2f", b*8/1000000}')
INTL_PING=$(ping_avg 1.1.1.1)
[ -z "$INTL_PING" ] && INTL_PING=""

# === RU ===
RU_RAW=$(curl -o /dev/null -s -m $TIMEOUT \
    -w "%{speed_download} %{time_total} %{http_code}" \
    "$RU_URL" 2>/dev/null)
RU_BPS=$(echo "$RU_RAW"  | awk '{print $1+0}')
RU_TIME=$(echo "$RU_RAW" | awk '{print $2+0}')
RU_HTTP=$(echo "$RU_RAW" | awk '{print $3+0}')
RU_MBPS=$(awk -v b="$RU_BPS" 'BEGIN{printf "%.2f", b*8/1000000}')
RU_PING=$(ping_avg ya.ru)
[ -z "$RU_PING" ] && RU_PING=""

# === SUMMARY (только эти строки парсит Python) ===
echo "INTL_MBPS=$INTL_MBPS"
echo "INTL_TIME=$INTL_TIME"
echo "INTL_HTTP=$INTL_HTTP"
echo "INTL_PING_MS=$INTL_PING"
echo "RU_MBPS=$RU_MBPS"
echo "RU_TIME=$RU_TIME"
echo "RU_HTTP=$RU_HTTP"
echo "RU_PING_MS=$RU_PING"
"""


def speedtest_verdict(intl_mbps: float | None,
                      ru_mbps: float | None,
                      intl_http: int | None = None,
                      ru_http: int | None = None) -> tuple[str, str, str]:
    """beta07 / F5: классификация результата спидтеста.

    Возвращает (verdict_code, emoji, human_label).
        verdict_code ∈ {'OK', 'WARN', 'FAIL', 'ERROR'}.

    Правила:
      - ERROR — если оба HTTP-кода != 200 или оба mbps None: тест провален.
      - FAIL  — intl/ru < 0.15 (или intl_mbps == 0): подкоп блокируется.
      - WARN  — intl/ru < 0.40: подкоп заметно медленнее RU.
      - OK    — intl/ru >= 0.40.
      - WARN  — если данных RU < 1 Mbps (нечего сравнивать).
    """
    # Полный отказ
    intl_ok_http = intl_http == 200
    ru_ok_http = ru_http == 200
    if (not intl_ok_http and not ru_ok_http) or (
        not intl_mbps and not ru_mbps
    ):
        return ("ERROR", "❌", "оба канала не ответили (нет данных)")

    if not intl_mbps or intl_mbps <= 0:
        return ("FAIL", "❌",
                "подкоп не отвечает (intl канал пуст)")

    if not ru_mbps or ru_mbps < 1:
        return ("WARN", "⚠️",
                "RU канал слишком медленный — сравнение неинформативно")

    ratio = intl_mbps / ru_mbps
    if ratio >= 0.40:
        return ("OK", "✅",
                f"подкоп нормально пропускает (intl/ru={ratio:.2f})")
    if ratio >= 0.15:
        return ("WARN", "⚠️",
                f"подкоп заметно медленнее RU (intl/ru={ratio:.2f})")
    return ("FAIL", "❌",
            f"подкоп блокируется или сильно замедлен (intl/ru={ratio:.2f})")


def _parse_speedtest_output(out: str) -> dict:
    """Парсит вывод SPEEDTEST_SCRIPT в dict с типизированными значениями."""
    result: dict = {
        "intl_mbps": None, "ru_mbps": None,
        "intl_ping_ms": None, "ru_ping_ms": None,
        "intl_http": None, "ru_http": None,
        "intl_time": None, "ru_time": None,
    }
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if "=" not in ln:
            continue
        key, _, val = ln.partition("=")
        val = val.strip()
        if not val:
            continue
        k = key.strip()
        if k in ("INTL_HTTP", "RU_HTTP"):
            try:
                result["intl_http" if k == "INTL_HTTP" else "ru_http"] = int(float(val))
            except (ValueError, TypeError):
                pass
        elif k in ("INTL_MBPS", "RU_MBPS",
                   "INTL_PING_MS", "RU_PING_MS",
                   "INTL_TIME", "RU_TIME"):
            try:
                result[k.lower()] = float(val)
            except (ValueError, TypeError):
                pass
    return result


def do_speedtest(r: Router, ssh_cfg: dict) -> dict:
    """beta07 / F5: запускает SPEEDTEST_SCRIPT на роутере.

    Возвращает dict:
        {
            "intl_mbps": float|None, "ru_mbps": float|None,
            "intl_ping_ms": float|None, "ru_ping_ms": float|None,
            "intl_http": int|None, "ru_http": int|None,
            "intl_time": float|None, "ru_time": float|None,
            "raw": str,           # полный вывод скрипта (для аудита)
            "error": str|None,    # SSH ошибка (если была) или None
            "verdict": str,       # OK/WARN/FAIL/ERROR
            "verdict_emoji": str,
            "verdict_label": str,
        }

    Никогда не выбрасывает — все ошибки кладёт в `error`.
    SSH timeout=90s (на сам curl уходит до 30+30 + ping ~10).
    """
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, err = s.run(SPEEDTEST_SCRIPT, timeout=90)
        raw = (out or "")
        if err and err.strip():
            raw += "\n--- stderr ---\n" + err
        parsed = _parse_speedtest_output(raw)
        v_code, v_emoji, v_label = speedtest_verdict(
            parsed["intl_mbps"], parsed["ru_mbps"],
            parsed["intl_http"], parsed["ru_http"],
        )
        parsed.update({
            "raw": raw,
            "error": None,
            "verdict": v_code,
            "verdict_emoji": v_emoji,
            "verdict_label": v_label,
        })
        return parsed
    except SSHError as e:
        return {
            "intl_mbps": None, "ru_mbps": None,
            "intl_ping_ms": None, "ru_ping_ms": None,
            "intl_http": None, "ru_http": None,
            "intl_time": None, "ru_time": None,
            "raw": str(e),
            "error": str(e),
            "verdict": "ERROR",
            "verdict_emoji": "❌",
            "verdict_label": f"SSH ошибка: {e}",
        }
    except Exception as e:
        return {
            "intl_mbps": None, "ru_mbps": None,
            "intl_ping_ms": None, "ru_ping_ms": None,
            "intl_http": None, "ru_http": None,
            "intl_time": None, "ru_time": None,
            "raw": str(e),
            "error": str(e),
            "verdict": "ERROR",
            "verdict_emoji": "❌",
            "verdict_label": f"внутренняя ошибка: {e}",
        }


def do_capture_client_log(r: Router, ssh_cfg: dict,
                          global_check_output: str = "") -> str:
    """Собирает для клиентского «отправить лог админу»:
       - переданный вывод global_check (если есть)
       - последние 100 строк logread | grep -Ei 'podkop|xray|sing-box'
       - снапшот uci show podkop (обрезан)

    Возвращает текст (уже объединённый). Никогда не падает — даже если SSH
    упал, вернёт сообщение об ошибке как часть лога."""
    script = r"""
echo "=== logread (tail 100 filtered) ==="
logread 2>/dev/null | grep -Ei 'podkop|xray|sing-box' | tail -n 100
echo ""
echo "=== uci show podkop (head 50) ==="
uci -q show podkop 2>/dev/null | head -n 50
echo ""
echo "=== pgrep sing-box ==="
pgrep -fa "sing-box" 2>/dev/null || echo "(no sing-box)"
echo ""
echo "=== nft list tables ==="
nft list tables 2>/dev/null | head -n 20
"""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=20)
        body = out or ""
        if err.strip():
            body += "\n--- stderr ---\n" + err
    except SSHError as e:
        body = f"(SSH failed while capturing tail: {e})"

    parts: list[str] = []
    if global_check_output.strip():
        parts.append("=== global_check output ===")
        parts.append(global_check_output.strip())
        parts.append("")
    parts.append(body)
    return "\n".join(parts).strip() + "\n"


# =============================================================================
# Stage 3 / A8: один per-router тест с PASS/WARN/FAIL вердиктом.
# =============================================================================

def do_router_selftest(r: Router, ssh_cfg: dict) -> tuple[str, list[str], str]:
    """Запускает короткий набор проверок на роутере и возвращает
    (verdict, lines, raw_output).

    verdict ∈ {'PASS', 'WARN', 'FAIL'}.

    Проверки (все в одном SSH-вызове):
      1. sing-box процесс
      2. PodkopTable в nftables
      3. local_ip (yandex.ru)
      4. egress_ip (ifconfig.co)
      5. egress ≠ local (трафик реально идёт через VLESS)
      6. DNS resolve youtube.com
      7. HTTP curl youtube.com

    FAIL: 1 или 2 упали (подкоп не работает).
    WARN: 5, 6 или 7 упали (подкоп жив, но трафик странный).
    PASS: всё ок."""
    script = r"""
SING=$(pgrep -f "^/usr/bin/sing-box" >/dev/null 2>&1 && echo 1 || echo 0)
TABLE=$(nft list tables 2>/dev/null | grep -q "PodkopTable" && echo 1 || echo 0)
LOCAL_IP=$(wget -qT5 -O- 'https://yandex.ru/internet/api/v0/ip/' 2>/dev/null | tr -d '"\n' || echo "")
EGRESS=$(wget -qT5 -O- 'https://ifconfig.co/json' 2>/dev/null || echo "")
DNS_YT=$(nslookup youtube.com 2>/dev/null | awk '/^Address/{a=$3} END{print a}')
HTTP_YT=$(wget --spider -qT10 https://youtube.com 2>&1 && echo 200 || echo fail)
echo "SING=$SING"
echo "TABLE=$TABLE"
echo "LOCAL_IP=$LOCAL_IP"
echo "EGRESS=$EGRESS"
echo "DNS_YT=$DNS_YT"
echo "HTTP_YT=$HTTP_YT"
"""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            rc, out, err = s.run(script, timeout=30)
    except SSHError as e:
        return "FAIL", [f"[FAIL] SSH: {e}"], str(e)

    # Парсинг
    sing = False
    table = False
    local_ip = ""
    egress_ip = ""
    egress_country = ""
    egress_city = ""
    dns_yt = ""
    http_yt = ""
    for ln in (out or "").splitlines():
        if ln.startswith("SING="):
            sing = ln.endswith("=1")
        elif ln.startswith("TABLE="):
            table = ln.endswith("=1")
        elif ln.startswith("LOCAL_IP="):
            local_ip = ln[len("LOCAL_IP="):].strip()
        elif ln.startswith("EGRESS="):
            raw = ln[len("EGRESS="):].strip()
            if raw:
                try:
                    j = json.loads(raw)
                    egress_ip = (j.get("ip") or "").strip()
                    egress_country = (j.get("country") or "").strip()
                    egress_city = (j.get("city") or "").strip()
                except Exception:
                    pass
        elif ln.startswith("DNS_YT="):
            dns_yt = ln[len("DNS_YT="):].strip()
        elif ln.startswith("HTTP_YT="):
            http_yt = ln[len("HTTP_YT="):].strip()

    lines: list[str] = []
    # 1, 2
    lines.append(f"[{'OK' if sing else 'FAIL'}] sing-box процесс {'жив' if sing else 'НЕ найден'}")
    lines.append(f"[{'OK' if table else 'FAIL'}] PodkopTable в nftables {'найдена' if table else 'НЕ найдена'}")
    # 3
    lines.append(f"[{'OK' if local_ip else 'WARN'}] local_ip: {local_ip or '(не получен)'}")
    # 4
    if egress_ip:
        extra = ""
        if egress_country:
            extra = f" ({egress_country}{(', ' + egress_city) if egress_city else ''})"
        lines.append(f"[OK] egress_ip: {egress_ip}{extra}")
    else:
        lines.append("[WARN] egress_ip: (не получен)")
    # 5: egress != local
    if egress_ip and local_ip:
        if egress_ip == local_ip:
            lines.append(f"[WARN] egress == local → трафик идёт мимо VLESS")
        else:
            lines.append(f"[OK] egress != local → трафик через VLESS")
    else:
        lines.append("[WARN] не могу сравнить egress/local (нет данных)")
    # 6: DNS
    if dns_yt:
        lines.append(f"[OK] DNS resolve youtube.com → {dns_yt}")
    else:
        lines.append("[WARN] DNS resolve youtube.com: нет ответа")
    # 7: HTTP
    if http_yt == "200":
        lines.append("[OK] curl https://youtube.com → 200 OK")
    else:
        lines.append(f"[WARN] curl https://youtube.com → {http_yt or 'нет ответа'}")

    # Вердикт
    verdict = "PASS"
    if not sing or not table:
        verdict = "FAIL"
    elif any(ln.startswith("[WARN]") for ln in lines):
        verdict = "WARN"

    return verdict, lines, out or ""


# =============================================================================
# YAML-редактор ярлыков (синхронизирован с r.py)
# =============================================================================

def cfg_edit_label(cfg_path: str | Path, action: str, rid: str, label: str = "") -> bool:
    """Редактирует overrides в /etc/r/config.yaml, сохраняя комментарии.

    action: 'add' | 'rename' | 'remove'
    rid: 'id07' (всегда idNN формат)
    label: имя владельца (для add / rename)

    Возвращает True если изменение записано.
    """
    p = Path(cfg_path)
    text = p.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Найти блок overrides:
    ov_idx = -1
    for i, line in enumerate(lines):
        if re.match(r"^overrides\s*:\s*$", line):
            ov_idx = i
            break
    if ov_idx < 0:
        lines.append("")
        lines.append("overrides:")
        ov_idx = len(lines) - 1

    # Определить границы блока (до следующего top-level ключа)
    end_idx = len(lines)
    for j in range(ov_idx + 1, len(lines)):
        s = lines[j]
        if s and not s.startswith(" ") and not s.startswith("#") and ":" in s:
            end_idx = j
            break

    # Индент внутри блока — 2 пробела по умолчанию
    indent = "  "

    # Regex для строк роутера (и активных, и закомментированных)
    active_re = re.compile(rf"^(\s*){re.escape(rid)}\s*:\s*(.+?)\s*$")
    commented_re = re.compile(rf"^(\s*)#\s*{re.escape(rid)}\s*:.*$")

    existing_idx = -1
    for j in range(ov_idx + 1, end_idx):
        if active_re.match(lines[j]) or commented_re.match(lines[j]):
            existing_idx = j
            break

    if action == "remove":
        if existing_idx < 0:
            return False
        # Заменяем на закомментированную «свободный»
        lines[existing_idx] = f"{indent}# {rid}: свободный"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

    if action in ("add", "rename"):
        if not label:
            return False
        safe_label = label.replace('"', '\\"')
        new_line = f'{indent}{rid}: "{safe_label}"'
        if existing_idx >= 0:
            lines[existing_idx] = new_line
        else:
            # Вставить в отсортированной позиции по rid
            insert_pos = end_idx
            for j in range(ov_idx + 1, end_idx):
                m_act = active_re.match(lines[j])
                m_cmt = commented_re.match(lines[j])
                m = m_act or m_cmt
                if m:
                    continue
                other = re.match(r"^\s*(#\s*)?(id\d{2})\s*:.*$", lines[j])
                if other and other.group(2) > rid:
                    insert_pos = j
                    break
            lines.insert(insert_pos, new_line)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

    return False
