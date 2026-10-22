"""Ограниченный супервизор без системных сетевых изменений."""

import fcntl
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from .config import VERSION, client, load, write
from .rules import Rules
from .transport import ssh_command


def log_tail(path, limit=4000):
    """Прочитать ограниченный конец журнала, сохранив исходную ошибку при отказе чтения.

    Parameters
    ----------
    path : pathlib.Path
        Путь к журналу процесса.
    limit : int
        Максимальное число байтов для чтения.

    Returns
    -------
    str
        Последние записи или пояснение ошибки чтения.
    """
    try:
        with path.open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - limit))
            return stream.read(limit).decode('utf-8', errors='replace').strip()
    except FileNotFoundError:
        return ''
    except OSError as error:
        return 'Журнал недоступен: ' + str(error)


def directory(root):
    path = root / ".runtime"
    if path.is_symlink():
        raise RuntimeError("Каталог состояния не может быть ссылкой")
    path.mkdir(mode=0o700, exist_ok=True)
    path.chmod(0o700)
    return path


def atomic(path, value):
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def locked(root):
    with open(directory(root) / "lock", "a", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def status(root):
    path = directory(root) / "state.json"
    value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"phase": "stopped"}
    value["running"] = locked(root)
    if not value["running"] and value["phase"] not in ("stopped", "failed"):
        value["phase"] = "interrupted"
    return value


def binary(root):
    path = root / "vendor/sing-box"
    import hashlib
    if not path.is_file() or not (root / "vendor/provenance.json").is_file():
        raise RuntimeError("Сначала выполните python3 tools/install_sing_box.py из каталога проекта")
    manifest = json.loads((root / "vendor/provenance.json").read_text(encoding="utf-8"))
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["binary_sha256"]:
        raise RuntimeError("Хеш sing-box не совпадает с сохраненным манифестом")
    text = subprocess.check_output([str(path), "version"], encoding="utf-8")
    if text.splitlines()[0] != "sing-box version " + VERSION:
        raise RuntimeError("Неподдерживаемая версия sing-box")
    return str(path)


def greeting(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4) as stream:
            stream.sendall(b"\x05\x01\x00")
            response = b""
            while len(response) < 2:
                chunk = stream.recv(2 - len(response))
                if not chunk:
                    return False
                response += chunk
            return response == b"\x05\x00"
    except OSError:
        return False


def free_ports(c, reuse_tcp=False):
    for key, kinds in (("listen_port", (socket.SOCK_STREAM, socket.SOCK_DGRAM)),
                       ("forward_port", (socket.SOCK_STREAM,)),
                       ("dns_port", (socket.SOCK_STREAM, socket.SOCK_DGRAM))):
        for kind in kinds:
            with socket.socket(socket.AF_INET, kind) as stream:
                if reuse_tcp and kind == socket.SOCK_STREAM:
                    # TIME_WAIT не означает работающий сервер; listen выявит живого владельца.
                    stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                stream.bind(("127.0.0.1", c[key]))
                if reuse_tcp and kind == socket.SOCK_STREAM:
                    stream.listen(1)


def terminate(children):
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
    for child in reversed(children):
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


class GuardedProcess:
    def __init__(self, command, stderr=None):
        read_fd, self.writer = os.pipe()
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(Path(__file__).with_name("guard.py")), str(read_fd), *command],
                pass_fds=(read_fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=stderr if stderr is not None else subprocess.DEVNULL, start_new_session=True)
        except BaseException:
            os.close(self.writer)
            self.writer = None
            raise
        finally:
            os.close(read_fd)

    def poll(self):
        return self.process.poll()

    def terminate(self):
        if self.writer is not None:
            os.close(self.writer)
            self.writer = None

    def wait(self, timeout=None):
        result = self.process.wait(timeout=timeout)
        self.terminate()
        return result

    def kill(self):
        self.terminate()
        self.process.kill()


def supervise(root, mode, run_id, test_command=None):
    os.umask(0o077)
    run = directory(root)
    with open(run / "lock", "a", encoding="utf-8") as guard:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 2
        logger = logging.getLogger("sshvpn")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = RotatingFileHandler(run / "events.log", maxBytes=131072, backupCount=2, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
        stopping = False
        children = []
        state = {"run_id": run_id, "mode": mode, "pid": os.getpid(), "phase": "starting", "restarts": 0}

        def save(phase, reason=None):
            state["phase"] = phase
            if reason is not None:
                state["last_failure"] = reason
            atomic(run / "state.json", state)
            logger.info("phase=%s restarts=%d", phase, state["restarts"])

        def signal_stop(*_):
            nonlocal stopping
            stopping = True

        def requested():
            nonlocal stopping
            path = run / "stop.json"
            if path.exists():
                try:
                    if json.loads(path.read_text(encoding="utf-8")).get("run_id") == run_id:
                        stopping = True
                except (ValueError, OSError):
                    pass
            return stopping

        signal.signal(signal.SIGTERM, signal_stop)
        signal.signal(signal.SIGINT, signal_stop)
        save("starting")
        try:
            c, rules = load(root), Rules.load(root)
            if mode not in ("trial", "full") or (mode == "full" and not c["backend_ready"]):
                raise RuntimeError("Серверная часть не принята")
            executable = binary(root)
            write(run / "client.json", client(c, rules, mode))
            subprocess.run([executable, "check", "-c", str(run / "client.json")], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            command = test_command if test_command is not None else ssh_command(c, mode)
            free_ports(c)
            while not requested():
                save("connecting")
                with open(run / 'ssh.log', 'w', encoding='utf-8') as log:
                    children.append(GuardedProcess(command, stderr=log))
                deadline = time.monotonic() + c["connect_timeout"] + 2
                while not requested() and time.monotonic() < deadline and children[0].poll() is None:
                    if greeting(c["forward_port"]):
                        break
                    time.sleep(0.1)
                if not requested() and children[0].poll() is None and greeting(c["forward_port"]):
                    with open(run / 'tun.log', 'w', encoding='utf-8') as log:
                        children.append(GuardedProcess([executable, "run", "-c", str(run / "client.json")], stderr=log))
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not greeting(c["listen_port"]) and not requested():
                        if children[-1].poll() is not None:
                            break
                        time.sleep(0.1)
                    if greeting(c["listen_port"]):
                        save("ready")
                        health_deadline = time.monotonic() + 5
                        while not requested() and all(p.poll() is None for p in children):
                            if time.monotonic() >= health_deadline:
                                if not greeting(c["forward_port"]):
                                    break
                                health_deadline = time.monotonic() + 5
                            time.sleep(0.2)
                logger.info('Завершение дочерних процессов: codes=%s', [p.poll() for p in children])
                for name in ('ssh', 'tun'):
                    path = run / (name + '.log')
                    if path.exists():
                        tail = log_tail(path, 2000)
                        if tail:
                            logger.info('Диагностика %s: %s', name, tail)
                terminate(children)
                children.clear()
                if requested():
                    break
                if state["restarts"] >= c["max_restarts"]:
                    save("failed", "transport_unavailable")
                    return 1
                state["restarts"] += 1
                save("backoff", "transport_unavailable")
                deadline = time.monotonic() + min(2 ** (state["restarts"] - 1), 16)
                while not requested() and time.monotonic() < deadline:
                    time.sleep(0.1)
            save("stopped")
            return 0
        except Exception as error:
            logger.exception('Ошибка супервизора')
            save("failed", type(error).__name__ + ': ' + str(error)[:2000])
            return 1
        finally:
            terminate(children)
            handler.close()
            logger.removeHandler(handler)


def start(root, mode):
    if mode == "system":
        raise RuntimeError("Системный запуск заблокирован до отдельного согласования и проверки отката. Доступна команда plan.")
    if locked(root):
        raise RuntimeError("Проект уже запущен")
    c = load(root)
    if mode == "full" and not c["backend_ready"]:
        raise RuntimeError("На выбранном сервере еще нет принятой серверной части; используйте trial")
    binary(root)
    free_ports(c)
    run_id = uuid.uuid4().hex
    child = subprocess.Popen([sys.executable, str(root / "vpn.py"), "_supervise", mode, run_id],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True, cwd=root)
    deadline = time.monotonic() + c["connect_timeout"] + 8
    while time.monotonic() < deadline:
        value = status(root)
        if value.get("run_id") == run_id and value["phase"] in ("ready", "failed"):
            return value
        if child.poll() is not None:
            raise RuntimeError("Супервизор завершился до готовности")
        time.sleep(0.2)
    return status(root)


def stop(root):
    value = status(root)
    if not value["running"]:
        return value
    atomic(directory(root) / "stop.json", {"run_id": value["run_id"]})
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and locked(root):
        time.sleep(0.1)
    value = status(root)
    if value["running"]:
        raise RuntimeError("Остановка еще не завершилась; PID других процессов не изменялся")
    return value
