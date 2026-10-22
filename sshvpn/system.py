"""Системный туннель macOS с отдельным процессом аварийного отката."""

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

from .config import client, load, write
from .routes import Journal, Route
from .rules import Rules
from .runtime import GuardedProcess, atomic, binary, free_ports, greeting, terminate, log_tail
from .transport import profile, ssh_command

STATE = Path("/private/var/run/ssh-split-vpn.json")
LOCK = Path("/private/var/run/ssh-split-vpn.lock")
PREFIXES = ("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")
TUN = "utun99"


class VPNConflictError(RuntimeError):
    def __init__(self, interfaces, clients):
        self.interfaces = interfaces
        self.clients = clients
        label = ', '.join(clients or interfaces)
        super().__init__('Другой VPN использует системные маршруты: ' + label)


def connected_vpn_clients():
    names = []
    try:
        listed = command(['/usr/sbin/scutil', '--nc', 'list'], timeout=3)
        for line in listed.splitlines():
            if '(Connected)' in line:
                matched = re.search(r'"([^"\r\n]+)"', line)
                if matched:
                    name = ''.join(c for c in matched[1] if c.isprintable())[:80]
                    if name:
                        names.append(name)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        # Открытое окно клиента не означает подключение; ищем процесс транспорта.
        processes = command(['/bin/ps', '-axo', 'comm='], timeout=3)
        if any(Path(line.strip()).name == 'amneziawg-go' for line in processes.splitlines()):
            names.append('AmneziaWG')
    except (OSError, subprocess.SubprocessError):
        pass
    return sorted(set(names))


def reject_vpn_conflict(kernel):
    routes = kernel.snapshot((*PREFIXES, '0.0.0.0/0', '::/0'))
    occupied = [route for prefix, route in routes.items() if route is not None and
                (prefix in PREFIXES or route.interface.startswith(('utun', 'ppp', 'ipsec')))]
    if occupied:
        raise VPNConflictError(sorted({route.interface for route in occupied}), connected_vpn_clients())


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, encoding="utf-8", timeout=kwargs.pop("timeout", 15),
                                   stderr=subprocess.STDOUT, **kwargs)


def canonical(value, family):
    if value == "default":
        return "0.0.0.0/0" if family == "inet" else "::/0"
    if "%" in value or value.startswith("link#"):
        return None
    host, slash, bits = value.partition("/")
    if family == "inet":
        parts = host.split(".")
        if not slash:
            bits = str(len(parts) * 8)
        host = ".".join(parts + ["0"] * (4 - len(parts)))
    elif not slash:
        bits = "128"
    try:
        return str(ipaddress.ip_network(host + "/" + bits, strict=False))
    except ValueError:
        return None


def parse_routes(text, family):
    result = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] == "Destination":
            continue
        prefix = canonical(parts[0], family)
        if prefix:
            result.append({"prefix": prefix, "gateway": parts[1], "flags": parts[2],
                           "interface": parts[3], "scope": "I" in parts[2]})
    return result


class MacRoutes:
    def rows(self):
        return [row for family in ("inet", "inet6") for row in parse_routes(
            command(["/usr/sbin/netstat", "-rn", "-f", family], timeout=3), family)]

    def get(self, prefix):
        return self.lookup(prefix, self.rows())

    @staticmethod
    def lookup(prefix, available):
        network, _, scope = prefix.partition("%")
        rows = [r for r in available if r["prefix"] == network and
                r["scope"] == bool(scope) and (not scope or r["interface"] == scope)]
        if len(rows) > 1:
            raise RuntimeError("Неоднозначный маршрут: " + prefix)
        if not rows:
            return None
        r = rows[0]
        gateway = "" if r["gateway"] == r["interface"] or r["gateway"].startswith("link#") else r["gateway"]
        return Route(prefix, r["interface"], gateway)

    def snapshot(self, prefixes):
        rows = self.rows()
        return {prefix: self.lookup(prefix, rows) for prefix in prefixes}

    def change(self, action, route):
        network, _, scope = route.prefix.partition("%")
        args = ["/sbin/route", "-n", action, "-inet6" if ":" in network else "-inet", "-net", network]
        if scope:
            args += ["-ifscope", scope]
        args += [route.gateway] if route.gateway else ["-interface", route.interface]
        command(args, timeout=3)

    def add(self, route):
        self.change("add", route)

    def delete(self, route):
        if self.get(route.prefix) != route:
            raise RuntimeError("Владелец маршрута изменился: " + route.prefix)
        self.change("delete", route)


def current():
    try:
        value = json.loads(STATE.read_text(encoding="utf-8"))
        descriptor = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                value["running"] = False
            except BlockingIOError:
                value["running"] = True
        finally:
            os.close(descriptor)
        if not value["running"] and value["phase"] not in ("stopped", "failed", "rollback_conflict"):
            value["phase"] = "interrupted"
        return value
    except FileNotFoundError:
        return {"running": False, "phase": "stopped"}


def request_stop(root):
    state = current()
    if state["running"]:
        atomic(root / ".runtime/system-stop.json", {"run_id": state["run_id"]})
    return state


def export(root):
    c = load(root)
    p = profile(c["ssh_alias"])
    return {"command": ssh_command(c, "full", p), "server_ip": p["hostname"][0]}


def dns_script(key, zone=""):
    if not key.startswith("State:/Network/Service/SSH-Split-") or any(c in key + zone for c in '\n\r"'):
        raise ValueError("Некорректный ключ временного DNS")
    return ("d.init\nd.add ServerAddresses * 172.31.255.2\n"
            'd.add SupplementalMatchDomains * "' + zone + '"\n'
            "d.add SearchOrder # 1\n"
            "add " + key + " temporary\n")


def rollback(path):
    journal = Journal(MacRoutes(), lambda entries: atomic(path, entries))
    if path.exists():
        journal.entries = json.loads(path.read_text(encoding="utf-8"))
    return journal.rollback()


def watchdog(path, descriptor, lease, interactive=False):
    # Процесс не зависит от чата, сети и основного супервизора.
    deadline = time.monotonic() + lease if lease else float("inf")
    heartbeat = time.monotonic()
    parent = os.getppid()
    closed = False
    started = time.time()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while time.monotonic() < deadline and time.monotonic() - heartbeat < 30:
                if selector.select(timeout=0.25):
                    data = os.read(descriptor, 4096)
                    if not data:
                        closed = True
                        break
                    if interactive:
                        # Готовый постоянный туннель ограничен активностью, а не сроком сеанса.
                        if b"R" in data:
                            deadline = float("inf")
                    heartbeat = time.monotonic()
    finally:
        os.close(descriptor)
        reason = ('control_channel_closed' if closed else 'heartbeat_timeout'
                  if time.monotonic() - heartbeat >= 30 else 'lease_expired')
        try:
            atomic(path.parent / 'watchdog-events.json', {'started': started, 'finished': time.time(),
                   'reason': reason, 'parent_pid': parent, 'journal': str(path)})
        except OSError:
            # Отказ записи диагностики не должен мешать аварийному откату.
            pass
        if not closed and os.getppid() == parent:
            # Зависший основной процесс не должен удерживать временный DNS.
            os.kill(parent, signal.SIGKILL)
        # При исчезновении супервизора его защитники закрывают TUN и DNS.
        conflicts = rollback(path)
        atomic(path.parent / "rollback-result.json", {"conflicts": conflicts})
        if interactive and (not closed or os.getppid() != parent):
            from .session import emergency_report
            emergency_report(path)


def run(root, duration=600, self_test=False, protected=False, fault=None, manual=False,
        interactive=False, on_state=None):
    if interactive and (self_test or protected or fault or manual or duration != 0):
        raise ValueError("Постоянное подключение требует отдельного интерактивного сеанса")
    if interactive and not sys.stdin.isatty():
        raise RuntimeError("Постоянное подключение требует локального терминала")
    if manual and (self_test or protected or fault or not 180 <= duration <= 600):
        raise ValueError("Ручная приемка требует отдельного сеанса на 180-600 секунд")
    if fault not in (None, "kill", "hang") or (fault and not (self_test or protected)):
        raise ValueError("Аварийная проба доступна только в ограниченном режиме")
    if not self_test and not protected and not manual and not interactive:
        from .recovery import require_acceptance
        require_acceptance()
    if os.geteuid() != 0:
        raise RuntimeError("Нужен административный запуск из терминала Mac; пароль вводится только в sudo")
    uid = int(os.environ.get("SUDO_UID", "0"))
    if uid == 0:
        raise RuntimeError("Запускайте через sudo из учетной записи владельца проекта")
    user = pwd.getpwuid(uid)
    if root.stat().st_uid != uid:
        raise RuntimeError("Владелец проекта не совпадает с SUDO_UID")
    if interactive:
        reject_vpn_conflict(MacRoutes())
    descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o644)
    os.fchmod(descriptor, 0o644)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise RuntimeError("Системный VPN уже запущен")
    children, dns, guard, heartbeat, key = [], None, None, None, None
    scratch = Path(tempfile.mkdtemp(prefix="ssh-split-system-", dir="/private/var/run"))
    journal_path = scratch / "routes.json"
    atomic(journal_path, [])
    run_id = uuid.uuid4().hex
    state = {"run_id": run_id, "mode": "interactive" if interactive else "manual" if manual else "protected" if protected else "system", "pid": os.getpid(), "owner_uid": uid,
             "phase": "preflight", "duration": duration, "journal": str(journal_path),
             "started_at": time.time()}
    stopping = False

    def save(phase, **values):
        state.update(phase=phase, **values)
        atomic(STATE, state)
        STATE.chmod(0o644)
        if on_state is None:
            print(json.dumps(state, ensure_ascii=False), flush=True)
        else:
            on_state(dict(state))

    def stop_signal(*_):
        nonlocal stopping
        stopping = True

    def requested():
        path = root / ".runtime/system-stop.json"
        try:
            return stopping or json.loads(path.read_text(encoding="utf-8")).get("run_id") == run_id
        except (FileNotFoundError, ValueError):
            return stopping

    def pulse():
        if guard is not None:
            if guard.poll() is not None:
                raise RuntimeError("Аварийный защитник завершился: останавливаем VPN")
            os.write(heartbeat, b".")

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGHUP, stop_signal)
    kernel = MacRoutes()
    journal = Journal(kernel, lambda entries: atomic(journal_path, entries))
    try:
        c, rules = load(root), Rules.load(root)
        if not self_test and not c["backend_ready"]:
            raise RuntimeError("Серверная часть не принята")
        if TUN in [name for _, name in socket.if_nameindex()]:
            raise RuntimeError("Интерфейс utun99 уже существует")
        executable = binary(root)
        free_ports(c, reuse_tcp=True)
        generated = client(c, rules, "system")
        write(scratch / "client.json", generated)
        command([executable, "check", "-c", str(scratch / "client.json")])
        clean_env = {"HOME": user.pw_dir, "USER": user.pw_name, "LOGNAME": user.pw_name,
                     "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONIOENCODING": "utf-8"}
        exported = json.loads(command([sys.executable, str(root / "vpn.py"), "_export-system"],
            user=uid, group=user.pw_gid, extra_groups=os.getgrouplist(user.pw_name, user.pw_gid), env=clean_env))
        if protected or self_test:
            from .protected import LimitedRoutes, baseline_routes
            if protected:
                baseline_routes(kernel)
            kernel = LimitedRoutes(kernel, c["physical_interface"], exported["server_ip"])
            journal.kernel = kernel
        if protected or manual:
            # Отдельный измеритель прямого выхода; пользовательские правила не меняются.
            generated["route"]["rules"].insert(2, {
                "domain": ["checkip.amazonaws.com"], "action": "route", "outbound": "direct"})
            generated["log"] = {"level": "info", "output": str(scratch / "engine.log")}
            write(scratch / "client.json", generated)
            command([executable, "check", "-c", str(scratch / "client.json")])
        atomic(scratch / "baseline.json", {"routes": kernel.rows(),
              "dns": command(["/usr/sbin/scutil", "--dns"]), "server_ip": exported["server_ip"]})
        read_fd, heartbeat = os.pipe()
        guard_command = [sys.executable, str(root / "vpn.py"), "_watchdog", str(journal_path),
                                  str(read_fd), str(30 if fault and self_test else
                                                    240 if protected else duration + 360 if manual else
                                                    600 if interactive else duration + 660 if duration else 0)]
        if interactive:
            guard_command.append("--interactive")
        guard = subprocess.Popen(guard_command,
                                 pass_fds=(read_fd,), start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(read_fd)
        save("armed", watchdog_pid=guard.pid)
        # При обычном запуске не ждем отключения: занятые маршруты сохраняются.
        if interactive:
            reject_vpn_conflict(kernel)
        elif not self_test and not protected:
            deadline = time.monotonic() + (120 if manual else 600)
            while any(kernel.get(p) is not None for p in PREFIXES):
                if state["phase"] != "awaiting_disconnect":
                    save("awaiting_disconnect")
                if requested() or time.monotonic() >= deadline:
                    raise RuntimeError("Другой VPN еще активен; маршруты не изменены")
                pulse()
                time.sleep(0.5)
        default = kernel.get("0.0.0.0/0")
        if default is None or default.interface != c["physical_interface"] or not default.gateway:
            raise RuntimeError("Не найден физический шлюз; сеть не изменена")
        if not self_test:
            scope = Route("0.0.0.0/0%" + c["physical_interface"], c["physical_interface"], default.gateway)
            existing = kernel.get(scope.prefix)
            if existing is None:
                journal.add(scope)
            elif existing != scope:
                raise RuntimeError("Существующий физический маршрут отличается")
            host = Route(exported["server_ip"] + "/32", c["physical_interface"], default.gateway)
            existing = kernel.get(host.prefix)
            if existing is None:
                journal.add(host)
            elif existing != host:
                raise RuntimeError("Существующий маршрут SSH-сервера отличается")
            save("ssh_connecting")
            with open(scratch / "ssh.log", "w", encoding="utf-8") as log:
                children.append(GuardedProcess(["/usr/bin/sudo", "-n", "-u", user.pw_name, "--", *exported["command"]],
                                               stderr=log))
            deadline = time.monotonic() + 20
            while not greeting(c["forward_port"]):
                pulse()
                if requested() or children[0].poll() is not None or time.monotonic() > deadline:
                    detail = log_tail(scratch / 'ssh.log', 2000)
                    raise RuntimeError("SSH через физический интерфейс не подключился: " + (detail or "нет ответа SOCKS"))
                time.sleep(0.2)
        save("tun_starting")
        with open(scratch / "tun.log", "w", encoding="utf-8") as log:
            children.append(GuardedProcess([executable, "run", "-c", str(scratch / "client.json")], stderr=log))
        deadline = time.monotonic() + 8
        while TUN not in [name for _, name in socket.if_nameindex()] or not greeting(c["listen_port"]):
            pulse()
            if children[-1].poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("TUN не запустился")
            time.sleep(0.1)
        destinations = (("192.0.2.123/32", "2001:db8:ffff::123/128") if self_test
                        else () if protected else PREFIXES)
        save("routes_configuring")
        for prefix in destinations:
            pulse()
            journal.add(Route(prefix, TUN))
        # Временный ключ исчезает при закрытии scutil, включая EOF после аварии.
        if not protected:
            save("dns_configuring")
            key = "State:/Network/Service/SSH-Split-" + run_id + "/DNS"
            with open(scratch / "dns.log", "w", encoding="utf-8") as log:
                dns = subprocess.Popen(["/usr/sbin/scutil"], stdin=subprocess.PIPE, stdout=log,
                                       stderr=subprocess.STDOUT, text=True, encoding="utf-8")
            dns.stdin.write(dns_script(key, "ssh-split-probe.invalid" if self_test else ""))
            dns.stdin.flush()
            pulse()
            time.sleep(0.5)
            shown = command(["/usr/sbin/scutil"], input="show " + key + "\nquit\n")
            if "172.31.255.2" not in shown or dns.poll() is not None:
                raise RuntimeError("Временный DNS не зарегистрирован")
        save("self_test" if self_test else "connecting" if interactive else "checking", dns_key=key,
             child_guard_pids=[p.process.pid for p in children])
        if self_test:
            if fault:
                save("fault_injected", fault=fault)
                os.kill(os.getpid(), signal.SIGKILL if fault == "kill" else signal.SIGSTOP)
                raise RuntimeError("Аварийная проба неожиданно продолжилась")
            raise InterruptedError("Проверка штатного отката после частичной настройки")
        if protected:
            from .protected import traffic
            result = traffic(c, journal, scratch, exported["server_ip"], pulse,
                             progress=lambda result: save("checking", probe=result))
            save("probe_complete", probe=result)
            if fault:
                save("fault_injected", fault=fault)
                os.kill(os.getpid(), signal.SIGKILL if fault == "kill" else signal.SIGSTOP)
                raise RuntimeError("Аварийная проба неожиданно продолжилась")
            return
        if manual:
            from .manual import traffic
            probe = traffic(c, scratch, exported["server_ip"], pulse,
                            progress=lambda result: save("checking", probe=result))
            save("checking", probe=probe)
        if interactive:
            os.write(heartbeat, b"R")
            save("ready", persistent=True, reconnects=0, expected_ip=exported["server_ip"],
                 connected_at=time.time())
        else:
            ip = command(["/usr/bin/curl", "--noproxy", "*", "-4fsS", "--max-time", "10", "https://api.ipify.org"]).strip()
            if ip != exported["server_ip"]:
                raise RuntimeError("Системный внешний IP не совпал с SSH-сервером")
            save("ready", external_ip=ip)
        deadline = time.monotonic() + duration if duration else float("inf")
        next_health, next_routes, failures = time.monotonic() + 15 if interactive else 0, 0, 0
        recovery_incidents = 0
        while not requested() and time.monotonic() < deadline:
            pulse()
            if children[-1].poll() is not None or dns.poll() is not None:
                raise RuntimeError("Процесс туннеля завершился")
            if time.monotonic() >= next_routes:
                routes = kernel.snapshot(("0.0.0.0/0", *PREFIXES))
                if routes["0.0.0.0/0"] != default:
                    raise RuntimeError("Физическая сеть изменилась: нужен повторный запуск")
                if any(routes[p] != Route(p, TUN) for p in PREFIXES):
                    raise RuntimeError("Маршруты VPN изменились")
                next_routes = time.monotonic() + 2
            if interactive and children[0].poll() is not None:
                from .session import reconnect
                recovery_incidents += 1
                if recovery_incidents > c["max_restarts"]:
                    raise RuntimeError("SSH повторно падает без успешной проверки выхода: выполняется откат")
                save("reconnecting", reconnects=state["reconnects"] + 1)
                children[0] = reconnect(children[0], exported["command"], user.pw_name,
                    scratch / "ssh.log", c, pulse, requested)
                next_health = 0
            elif children[0].poll() is not None:
                raise RuntimeError("Процесс SSH завершился")
            if time.monotonic() >= next_health:
                # Не сохраняем содержимое трафика; проверяем фактический выход.
                try:
                    if interactive:
                        from .session import healthy
                        ok = healthy(exported["server_ip"], pulse)
                    else:
                        ip = command(["/usr/bin/curl", "--noproxy", "*", "-4fsS", "--max-time", "5", "https://api.ipify.org"]).strip()
                        ok = ip == exported["server_ip"]
                    failures = 0 if ok else failures + 1
                except subprocess.SubprocessError:
                    failures += 1
                save(state['phase'], last_health_check=time.time(), consecutive_health_failures=failures,
                     health_checks=state.get('health_checks', 0) + 1)
                if failures >= 3:
                    if not interactive or state.get("health_reconnect_pending"):
                        raise RuntimeError("Три проверки выхода не прошли: аварийный откат")
                    from .session import reconnect
                    recovery_incidents += 1
                    save("reconnecting", reconnects=state["reconnects"] + 1,
                         health_reconnect_pending=True)
                    children[0] = reconnect(children[0], exported["command"], user.pw_name,
                        scratch / "ssh.log", c, pulse, requested)
                    failures = 0
                elif failures == 0 and interactive:
                    recovery_incidents = 0
                    save("ready", health_reconnect_pending=False, last_health=time.time(),
                         external_ip=exported["server_ip"])
                next_health = time.monotonic() + 15
            time.sleep(0.5)
        save("stopping")
    except InterruptedError as error:
        save("self_test_rollback" if self_test else "stopping", reason=str(error))
    except BaseException as error:
        failure_phase = state['phase']
        detail = error.output if isinstance(error, subprocess.CalledProcessError) else ""
        reason = str(error) + ("\n" + str(detail)[-2000:] if detail else "")
        if protected:
            log = scratch / "engine.log"
            if log.exists():
                state["diagnostic_log"] = log_tail(log, 8000)
        diagnostics = {'traceback': traceback.format_exc()[-12000:]}
        for name in ('ssh', 'tun', 'dns'):
            path = scratch / (name + '.log')
            if path.exists():
                diagnostics[name + '_stderr'] = log_tail(path)
        save("failed", reason=reason, failure_phase=failure_phase, diagnostics=diagnostics,
             child_exit_codes=[p.poll() for p in children])
        raise
    finally:
        cleanup_started = time.monotonic()
        errors = []
        if dns is not None:
            try:
                dns.stdin.close()
                dns.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    dns.kill()
                    dns.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired) as error:
                    errors.append(str(error))
        if heartbeat is not None:
            os.close(heartbeat)
        if guard is not None:
            try:
                guard.wait(timeout=25)
            except subprocess.TimeoutExpired:
                guard.kill()
                guard.wait(timeout=3)
                errors.append("Аварийный защитник не завершился вовремя")
        try:
            errors.extend(rollback(journal_path))
        except Exception as error:
            errors.append(str(error))
        try:
            terminate(children)
        except Exception as error:
            errors.append(str(error))
        if TUN in [name for _, name in socket.if_nameindex()]:
            errors.append("Интерфейс TUN остался после остановки")
        if key:
            try:
                shown = command(["/usr/sbin/scutil"], input="show " + key + "\nquit\n", timeout=3)
                if "172.31.255.2" in shown:
                    errors.append("Временный DNS остался после остановки")
            except Exception as error:
                errors.append(str(error))
        try:
            # Штатный откат может завершиться в родителе после отказа защитника.
            atomic(scratch / "cleanup-result.json", {"conflicts": errors,
                   "watchdog_returncode": guard.returncode if guard is not None else None})
            save("rollback_conflict" if errors else "stopped", rollback_conflicts=errors,
                 stopped_at=time.time(), cleanup_seconds=round(time.monotonic() - cleanup_started, 3),
                 child_exit_codes=[p.poll() for p in children],
                 self_test_passed=self_test and not errors and state.get("phase") == "self_test_rollback")
        finally:
            os.close(descriptor)
