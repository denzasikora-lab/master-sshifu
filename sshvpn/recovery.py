"""Независимое восстановление VPN по локальному таймеру launchd."""

import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time
import uuid

from .runtime import atomic, directory

APP = "/Applications/AmneziaVPN.app"
EXE = APP + "/Contents/MacOS/AmneziaVPN"
LABEL = "local.ssh-split-vpn.recovery"
PREFS = Path.home() / "Library/Preferences/org.amneziavpn.AmneziaVPN.plist"
LIVE_RECOVERY_ACCEPTED = False


def require_acceptance():
    if not LIVE_RECOVERY_ACCEPTED:
        raise RuntimeError("Автопереключение заблокировано до отдельной приемки восстановления; доступен только dry-run")


def call(args, timeout=10):
    return subprocess.check_output(args, text=True, encoding="utf-8", timeout=timeout,
                                   stderr=subprocess.DEVNULL).strip()


def preferences(path=None):
    values = plistlib.loads((path or PREFS).read_bytes())
    # Старый defaultServerIndex не соответствует текущему defaultServerId.
    # Числовой индекс CLI нельзя получать из этого устаревшего поля.
    settings = {k: values.get(k) for k in ("Conf.routeMode", "Conf.sitesSplitTunnelingEnabled",
                "Conf.appsRouteMode", "Conf.autoConnect", "Conf.killSwitchEnabled", "Conf.ExceptSites")}
    return {"server_id": values.get("Servers.defaultServerId"),
            "servers_sha256": hashlib.sha256(values["Servers.serversList"]).hexdigest(),
            "settings_sha256": hashlib.sha256(plistlib.dumps(settings, sort_keys=True)).hexdigest(),
            "auto_connect": values.get("Conf.autoConnect", False)}


def ipv4():
    for endpoint in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
        try:
            value = call(["/usr/bin/curl", "--noproxy", "*", "-4fsS", "--connect-timeout", "3",
                          "--max-time", "5", endpoint], timeout=6)
            return str(ipaddress.IPv4Address(value))
        except (ValueError, OSError, subprocess.SubprocessError):
            pass
    return None


def pids():
    result = subprocess.run(["/usr/bin/pgrep", "-x", "AmneziaVPN"], text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    found = []
    for value in result.stdout.split():
        if value.isdigit():
            pid = int(value)
            try:
                if call(["/bin/ps", "-p", str(pid), "-o", "comm="]) == EXE:
                    found.append(pid)
            except subprocess.SubprocessError:
                pass
    return found


def ensure_profile(snapshot):
    live = preferences()
    for name in ("servers_sha256", "settings_sha256", "server_id"):
        if live[name] != snapshot[name]:
            raise RuntimeError("Настройки Amnezia изменились после постановки таймера: " + name)
    # Автоподключение вместе с --connect может дать двойное переключение.
    if live["auto_connect"]:
        raise RuntimeError("Для этого адаптера требуется проверка поведения autoConnect")
    if type(snapshot.get("verified_cli_index")) is not int or snapshot["verified_cli_index"] < 0:
        raise RuntimeError("Нет отдельно проверенного соответствия CLI-индекса и идентификатора сервера")


def connected_amnezia(expected):
    if not pids():
        return False
    try:
        route = call(["/sbin/route", "-n", "get", "1.1.1.1"])
        return "utun" in route and ipv4() == expected
    except (OSError, subprocess.SubprocessError):
        return False


def stop_test(root, snapshot):
    from .system import current, request_stop
    state = current()
    if state["running"]:
        if state.get("owner_uid") != os.getuid():
            raise RuntimeError("Запущенный системный тест принадлежит другому пользователю")
        request_stop(root)
        end = time.monotonic() + 45
        while current()["running"] and time.monotonic() < end:
            time.sleep(0.2)
        if current()["running"]:
            raise RuntimeError("Системный тест не остановился; ожидаем его независимый watchdog")


def restore(root, snapshot, event):
    require_acceptance()
    ensure_profile(snapshot)
    if snapshot.get("happ_id"):
        raise RuntimeError("Автоматический резерв Happ не принят и отключен")
    stop_test(root, snapshot)
    if connected_amnezia(snapshot["expected_ip"]):
        event("restored", provider="amnezia", external_ip=snapshot["expected_ip"], already_connected=True)
        return True
    # Повторный запуск приложения по номеру профиля удален после инцидента.
    # Откат ограниченного теста выполняет отдельный защитник маршрутов.
    event("failed", reason="Исходное подключение не подтвердилось; перезапуск Amnezia запрещен")
    return False


def locations(root):
    run = directory(root) / "recovery"
    run.mkdir(mode=0o700, exist_ok=True)
    return run


def status(root):
    path = locations(root) / "state.json"
    if not path.exists():
        return {"phase": "not_armed"}
    return json.loads(path.read_text(encoding="utf-8"))


def arm(root, seconds, expected_ip, dry_run=False, allow_happ=False):
    if not dry_run:
        require_acceptance()
    if allow_happ:
        raise RuntimeError("Автоматический резерв Happ не принят и отключен")
    if os.geteuid() == 0:
        raise RuntimeError("Таймер запускается от обычного пользователя, без sudo")
    if not 5 <= seconds <= 3600:
        raise ValueError("Таймер должен быть от 5 до 3600 секунд")
    previous = status(root)
    if previous.get("phase") in ("arming", "armed", "recovering", "connecting"):
        raise RuntimeError("Таймер уже поставлен; сначала проверьте текущий сеанс")
    snapshot = preferences()
    if snapshot["auto_connect"]:
        raise RuntimeError("Сначала нужна проверка взаимодействия autoConnect и --connect")
    expected = str(ipaddress.IPv4Address(expected_ip))
    if not connected_amnezia(expected):
        raise RuntimeError("Не подтверждено исходное работающее подключение Amnezia")
    snapshot.update(expected_ip=expected, happ_id=None,
                    deadline=time.time() + seconds, dry_run=dry_run, run_id=uuid.uuid4().hex,
                    created=time.time(), max_recovery_seconds=240)
    run = locations(root)
    atomic(run / "snapshot.json", snapshot)
    atomic(run / "state.json", {"phase": "arming", "run_id": snapshot["run_id"], "deadline": snapshot["deadline"]})
    job = {"Label": LABEL, "ProgramArguments": [sys.executable, str(root / "vpn.py"), "_recovery-worker"],
           "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 3,
           "ProcessType": "Background", "AbandonProcessGroup": True,
           "StandardOutPath": str(run / "launchd.log"), "StandardErrorPath": str(run / "launchd.log"),
           "EnvironmentVariables": {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                    "PYTHONIOENCODING": "utf-8"}}
    path = run / "recovery.plist"
    path.write_bytes(plistlib.dumps(job))
    path.chmod(0o600)
    subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    call(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)])
    end = time.monotonic() + 10
    while time.monotonic() < end:
        live = status(root)
        if live.get("run_id") == snapshot["run_id"] and live.get("phase") == "armed":
            return live
        time.sleep(0.2)
    raise RuntimeError("launchd не подтвердил готовность таймера; отключать VPN нельзя")


def cancel(root):
    live = status(root)
    if live.get("phase") != "armed":
        raise RuntimeError("Отменять можно только ожидающий таймер")
    atomic(locations(root) / "cancel.json", {"run_id": live["run_id"]})
    return {"cancel_requested": live["run_id"]}


def worker(root):
    run = locations(root)
    with open(run / "lock", "a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        snapshot = json.loads((run / "snapshot.json").read_text(encoding="utf-8"))
        live = status(root)
        if live.get("run_id") == snapshot["run_id"] and live.get("phase") in ("restored", "failed", "cancelled", "dry_run_passed"):
            return 0

        def event(phase, **fields):
            value = {"phase": phase, "run_id": snapshot["run_id"], "deadline": snapshot["deadline"],
                     "time": time.time(), "pid": os.getpid(), **fields}
            atomic(run / "state.json", value)
            with open(run / "events.jsonl", "a", encoding="utf-8") as stream:
                stream.write(json.dumps(value, ensure_ascii=False) + "\n")

        # Отдельный caffeinate действует только на время испытания и восстановления.
        awake = subprocess.Popen(["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not snapshot["dry_run"]:
                require_acceptance()
            event("armed", dry_run=snapshot["dry_run"], expected_ip=snapshot["expected_ip"])
            while time.time() < snapshot["deadline"]:
                try:
                    if json.loads((run / "cancel.json").read_text(encoding="utf-8")).get("run_id") == snapshot["run_id"]:
                        event("cancelled")
                        return 0
                except (FileNotFoundError, ValueError):
                    pass
                time.sleep(0.25)
            if snapshot["dry_run"]:
                event("dry_run_passed", external_ip=ipv4())
                return 0
            if time.time() > snapshot["deadline"] + snapshot["max_recovery_seconds"]:
                event("failed", reason="Истекло ограниченное окно восстановления")
                return 0
            event("recovering")
            restore(root, snapshot, event)
            return 0
        except Exception as error:
            event("failed", reason=type(error).__name__ + ": " + str(error))
            return 0
        finally:
            if awake.poll() is None:
                awake.terminate()
            awake.wait(timeout=3)
