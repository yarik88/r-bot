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
        num = p % 100
        rid = f"id{num:02d}"
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

POLL_SCRIPT = r"""
echo "---UPTIME---"
cat /proc/uptime 2>/dev/null | awk '{print int($1)}' || echo 0
echo "---PODKOP---"
if [ -x /etc/init.d/podkop ]; then
  /etc/init.d/podkop running >/dev/null 2>&1 && echo RUN || echo STOP
elif command -v service >/dev/null 2>&1; then
  service podkop status >/dev/null 2>&1 && echo RUN || echo STOP
else
  echo UNKNOWN
fi
echo "---WAN---"
( ifstatus wan 2>/dev/null | awk -F'"' '/\"address\"/ {print $4; exit}' ) || echo ""
echo "---VLESS---"
uci -q get podkop.main.proxy_string || echo ""
echo "---END---"
"""

CHECK_CMD = "/usr/bin/podkop global_check 2>&1 || true"


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
    """Достаёт кусок между ---NAME--- и следующим ---X--- маркером."""
    m = re.search(rf"---{name}---\n(.*?)(?=---[A-Z]+---|\Z)", out, re.DOTALL)
    return m.group(1).strip() if m else ""


@dataclass
class PollResult:
    online: bool = False
    uptime: str = "—"
    podkop: str = "UNKNOWN"
    wan_ip: str = ""
    vless: str = ""
    error: str = ""


def poll_router(r: Router, ssh_cfg: dict) -> PollResult:
    """Один роутер — быстрый опрос по SSH."""
    try:
        with SSH(
            host=ssh_cfg.get("host", "127.0.0.1"),
            port=r.ssh_port,
            user=ssh_cfg.get("user", "root"),
            password=ssh_cfg["password"],
            timeout=ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, _ = s.run(POLL_SCRIPT, timeout=12)
        upsec = int((_section(out, "UPTIME") or "0").splitlines()[0] or 0)
        return PollResult(
            online=True,
            uptime=_format_uptime(upsec),
            podkop=_section(out, "PODKOP") or "UNKNOWN",
            wan_ip=_section(out, "WAN") or "",
            vless=_section(out, "VLESS") or "",
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


def do_global_check(r: Router, ssh_cfg: dict) -> tuple[bool, str, str]:
    """Запускает /usr/bin/podkop global_check, возвращает (verdict_ok, tail, full_text)."""
    try:
        with SSH(
            ssh_cfg.get("host", "127.0.0.1"),
            r.ssh_port,
            ssh_cfg.get("user", "root"),
            ssh_cfg["password"],
            ssh_cfg.get("connect_timeout", 8),
        ) as s:
            _, out, err = s.run(CHECK_CMD, timeout=60)
    except SSHError as e:
        return False, str(e), str(e)

    full = (out or "") + (("\n--- stderr ---\n" + err) if err.strip() else "")
    lower = full.lower()
    ok = True
    if any(bad in lower for bad in ("error", "fail", "timeout", "unreachable")):
        ok = False
    if any(good in lower for good in ("success", "works", "ok", "passed")):
        ok = ok or True
    return ok, full, full


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
