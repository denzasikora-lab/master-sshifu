"""Ограниченная приемка TUN и отката при сохранении работающего VPN."""

from dataclasses import asdict
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import time

from . import recovery, system
from .routes import Route
from .config import load
from .runtime import atomic, free_ports, status

REPORT = Path("/private/var/run/ssh-split-protected-check.json")
CHECK_LOCK = Path("/private/var/run/ssh-split-protected-check.lock")
FAKE = ipaddress.ip_network("198.18.0.0/15")


class LimitedRoutes:
    def __init__(self, kernel, physical, server_ip):
        self.kernel = kernel
        default = kernel.get("0.0.0.0/0")
        if not default or default.interface != physical or not default.gateway:
            raise RuntimeError("Физический шлюз не подтвержден")
        self.allowed = {Route("0.0.0.0/0%" + physical, physical, default.gateway),
                        Route(str(ipaddress.IPv4Address(server_ip)) + "/32", physical, default.gateway),
                        Route("192.0.2.123/32", system.TUN), Route("2001:db8:ffff::123/128", system.TUN)}

    def rows(self):
        return self.kernel.rows()

    def get(self, prefix):
        return self.kernel.get(prefix)

    def add(self, route):
        network = ipaddress.ip_network(route.prefix.partition("%")[0])
        fake_host = (network.version == 4 and network.prefixlen == 32 and
                     network.network_address in FAKE and route.interface == system.TUN and not route.gateway)
        if route not in self.allowed and not fake_host:
            raise RuntimeError("Ограниченный тест запрещает этот маршрут: " + route.prefix)
        self.kernel.add(route)

    def delete(self, route):
        self.kernel.delete(route)


def baseline_routes(kernel):
    routes = {prefix: kernel.get(prefix) for prefix in system.PREFIXES}
    first, second = routes[system.PREFIXES[0]], routes[system.PREFIXES[1]]
    if (not first or not second or first.interface != second.interface or
            not first.interface.startswith("utun") or first.interface == system.TUN):
        raise RuntimeError("Не подтверждены сохраненные основные маршруты работающего VPN")
    return {prefix: asdict(route) if route else None for prefix, route in routes.items()}


def fake_address(host, port):
    output = system.command(["/usr/bin/dig", "@127.0.0.1", "-p", str(port), host,
                             "A", "+short", "+time=2", "+tries=1"], timeout=4)
    addresses = [ipaddress.ip_address(line) for line in output.splitlines() if line.strip()]
    if len(addresses) != 1 or addresses[0] not in FAKE:
        raise RuntimeError("DNS не вернул единственный тестовый адрес для " + host)
    return str(addresses[0])


def fetch(host, path, scratch, address=None, interface=None):
    target = scratch / (host + ".body")
    args = ["/usr/bin/curl", "--noproxy", "*", "-4sS", "--connect-timeout", "5", "--max-time", "20",
            "--max-filesize", "9000000", "-o", str(target), "-w", "%{http_code} %{size_download} %{time_total}"]
    if address:
        args += ["--resolve", host + ":443:" + address]
    if interface:
        args += ["--interface", interface]
    text = system.command(args + ["https://" + host + path], timeout=22)
    code, size, elapsed = text.split()
    result = {"host": host, "http_status": int(code), "bytes": int(size), "seconds": float(elapsed)}
    if target.stat().st_size != result["bytes"]:
        raise RuntimeError("Неполная передача " + host)
    return result, target


def traffic(c, journal, scratch, server_ip, pulse, progress=lambda result: None):
    results = {}

    def probe(host, path="/"):
        pulse()
        address = fake_address(host, c["dns_port"])
        route = Route(address + "/32", system.TUN)
        if journal.kernel.get(route.prefix) is None:
            journal.add(route)
        if journal.kernel.get(route.prefix) != route:
            raise RuntimeError("Тестовый адрес занят чужим маршрутом")
        value, target = fetch(host, path, scratch, address=address)
        results[host] = value
        progress(results)
        pulse()
        return value, target

    value, target = probe("api.ipify.org")
    if value["http_status"] != 200 or target.read_text(encoding="utf-8").strip() != server_ip:
        raise RuntimeError("Выход TUN не совпал с SSH-сервером")
    results["ssh_external_ip"] = server_ip
    progress(results)
    ru, _ = probe("yandex.ru")
    log = (scratch / "engine.log").read_text(encoding="utf-8")
    results["ru_direct_log_verified"] = any(
        "outbound/direct[direct]" in line and "yandex.ru:443" in line for line in log.splitlines())
    progress(results)
    if not 200 <= ru["http_status"] < 400 or not results["ru_direct_log_verified"]:
        raise RuntimeError("Прямой ответ ru через TUN не подтвержден")
    for host in ("www.youtube.com", "www.speedtest.net"):
        probe(host)
    try:
        value, target = probe("checkip.amazonaws.com")
        direct = str(ipaddress.IPv4Address(target.read_text(encoding="utf-8").strip()))
        plain, target = fetch("checkip.amazonaws.com", "/", scratch, interface=c["physical_interface"])
        if (value["http_status"] != 200 or plain["http_status"] != 200 or
                target.read_text(encoding="utf-8").strip() != direct or direct == server_ip):
            raise RuntimeError("Прямой выход TUN не подтвержден сравнением с физическим интерфейсом")
        results["direct_external_ip"] = direct
    except (subprocess.SubprocessError, ValueError) as error:
        # Отказ внешнего измерителя не отменяет отдельную проверку прямого ru.
        results["direct_ip_probe_error"] = str(error)
        results["direct_external_ip_verified"] = False
    progress(results)
    value, target = probe("speed.cloudflare.com", "/__down?bytes=8388608")
    if value["http_status"] != 200 or value["bytes"] != 8388608:
        raise RuntimeError("Контрольная загрузка не завершена")
    value["mbit_per_second"] = round(value["bytes"] * 8 / value["seconds"] / 1_000_000, 2)
    # Ответ страницы не подтверждает воспроизведение видео или полный Speedtest.
    results.update(youtube_playback_verified=False, speedtest_completed=False, standalone_vpn_verified=False)
    return results


def cleanup_snapshot(state, ports=None):
    folder = Path(state["journal"]).parent
    marker = folder / "cleanup-result.json"
    if not marker.exists():
        marker = folder / "rollback-result.json"
    value = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else None
    pending = []
    if value is None:
        pending.append("Нет итогового файла отката")
    elif value.get("conflicts") != []:
        pending.append("Конфликт отката: " + repr(value.get("conflicts")))
    tun_present = system.TUN in [name for _, name in socket.if_nameindex()]
    if tun_present:
        pending.append("TUN еще существует")
    entries = json.loads(Path(state["journal"]).read_text(encoding="utf-8"))
    kernel, routes = system.MacRoutes(), []
    for entry in entries:
        original = Route(**entry["route"])
        current = kernel.get(original.prefix)
        routes.append({"original": entry["route"], "phase": entry["phase"],
                       "current": asdict(current) if current else None,
                       "physical_route_present_after_removal": entry["phase"] == "removed" and
                           current == original and original.interface != system.TUN})
        # После записанного удаления физический маршрут может создать новый VPN
        # или ядро. Совпадение адреса не возвращает проекту право владения им.
        if entry["phase"] != "removed" or (current == original and original.interface == system.TUN):
            pending.append("Маршрут не очищен: " + original.prefix)
    dns_present = False
    if state.get("dns_key"):
        shown = system.command(["/usr/sbin/scutil"], input="show " + state["dns_key"] + "\nquit\n")
        dns_present = "172.31.255.2" in shown
        if dns_present:
            pending.append("Временный DNS еще существует")
    if ports is not None:
        try:
            free_ports(ports, reuse_tcp=True)
        except OSError as error:
            pending.append("Порты еще заняты: " + str(error))
    return {"verified": not pending, "pending": pending, "marker": str(marker),
            "marker_value": value, "tun_present": tun_present,
            "dns_present": dns_present, "routes": routes}


def wait_cleanup(state, timeout=12, ports=None):
    end, last = time.monotonic() + timeout, None
    while time.monotonic() < end:
        last = cleanup_snapshot(state, ports)
        if last["verified"]:
            return {"conflicts": []}
        time.sleep(0.1)
    raise RuntimeError("Очистка не подтверждена в срок: " + "; ".join(
        last["pending"] if last else ["нет попыток проверки"]))


def audit_cleanup(root):
    if os.geteuid() != 0:
        raise RuntimeError("Для чтения закрытого журнала нужен sudo; сеть не меняется")
    state = system.current()
    if state["running"] or status(root)["running"]:
        raise RuntimeError("Сначала дождитесь завершения текущего сеанса")
    if not state.get("journal"):
        raise RuntimeError("Нет системного сеанса для проверки")
    report = {"checked_at": time.time(), "run_id": state["run_id"],
              "state_phase": state["phase"], "state_conflicts": state.get("rollback_conflicts"),
              "historical_timeout_cause_confirmed": False,
              "cleanup": cleanup_snapshot(state, load(root)), "network_changed": False}
    target = Path("/private/var/run/ssh-split-cleanup-audit.json")
    atomic(target, report)
    target.chmod(0o644)
    return report


def check(root, expected_ip):
    if os.geteuid() != 0 or int(os.environ.get("SUDO_UID", "0")) == 0:
        raise RuntimeError("Запустите protected-check через sudo из учетной записи владельца проекта")
    user = pwd.getpwuid(int(os.environ["SUDO_UID"]))
    if root.stat().st_uid != user.pw_uid:
        raise RuntimeError("Владелец проекта не совпадает с SUDO_UID")
    lock = os.open(CHECK_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return check_locked(root, expected_ip, user)
    finally:
        os.close(lock)


def check_locked(root, expected_ip, user):
    expected = str(ipaddress.IPv4Address(expected_ip))
    if system.current()["running"] or status(root)["running"]:
        raise RuntimeError("Сначала завершите другой тест проекта")
    kernel = system.MacRoutes()
    before = baseline_routes(kernel)
    prefs = Path(user.pw_dir) / "Library/Preferences/org.amneziavpn.AmneziaVPN.plist"
    profile = recovery.preferences(prefs)
    app_pids = recovery.pids()
    if not app_pids or recovery.ipv4() != expected:
        raise RuntimeError("Исходное подключение не подтверждено; сеть не изменена")
    dns = system.command(["/usr/sbin/scutil", "--dns"])
    report = {"phase": "checking", "expected_ip": expected, "stages": [],
              "amnezia_restart_attempted": False, "standalone_vpn_verified": False,
              "started": time.time()}

    def save():
        atomic(REPORT, report)
        REPORT.chmod(0o644)
        print(json.dumps(report, ensure_ascii=False), flush=True)

    def unchanged():
        if baseline_routes(kernel) != before or recovery.preferences(prefs) != profile or recovery.pids() != app_pids:
            raise RuntimeError("Состояние исходного VPN изменилось; продолжение запрещено")
        if system.command(["/usr/sbin/scutil", "--dns"]) != dns or recovery.ipv4() != expected:
            raise RuntimeError("Исходные DNS или внешний доступ не подтвердились")

    save()
    try:
        for stage in ("kill", "hang", "traffic"):
            unchanged()
            print("Ограниченная проверка: " + stage, flush=True)
            child = subprocess.Popen([sys.executable, str(root / "vpn.py"), "_protected-worker", stage],
                                     stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                code = child.wait(timeout=260 if stage == "traffic" else 50)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                state = system.current()
                if state.get("pid") != child.pid:
                    raise RuntimeError("Дочерний тест не зарегистрировал свое состояние")
                cleanup = wait_cleanup(state, ports=load(root))
                unchanged()
            if code != -signal.SIGKILL or state.get("phase") != "interrupted" or not state.get("fault"):
                report["partial_probe"] = state.get("probe")
                report["diagnostic_log"] = state.get("diagnostic_log")
                raise RuntimeError(state.get("reason") or "Аварийная проба не достигла ожидаемого состояния")
            if stage == "traffic" and not state.get("probe"):
                raise RuntimeError("Передача через TUN не подтверждена")
            state.update(phase="stopped", running=False, rollback_conflicts=[], protected_recovery_passed=True)
            atomic(system.STATE, state)
            system.STATE.chmod(0o644)
            report["stages"].append({"stage": stage, "cleanup": cleanup,
                                     "journal": state["journal"], "probe": state.get("probe")})
            save()
        report.update(phase="passed", limited_route_recovery_verified=True, finished=time.time())
    except BaseException as error:
        report.update(phase="failed", reason=str(error), finished=time.time())
        raise
    finally:
        save()
    return report
