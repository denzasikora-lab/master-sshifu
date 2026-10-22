"""Повторяемые замеры загрузки и отдачи с Mac через изолированный SSH."""

from datetime import datetime, timezone
import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time

from .config import CIPHERS, load
from .runtime import atomic, directory, greeting, terminate
from .transport import profile, ssh_command
from . import streamcheck


def curl(port, destination, upload=None, download_bytes=None):
    metrics = '{"code":%{http_code},"downloaded":%{size_download},"uploaded":%{size_upload},"seconds":%{time_total},"first_byte":%{time_starttransfer}}'
    command = ["/usr/bin/curl", "--noproxy", "", "--fail", "--silent", "--show-error",
               "--proto", "=https", "--connect-timeout", "10", "--max-time", "60",
               "--socks5-hostname", f"127.0.0.1:{port}", "-o", str(destination), "-w", metrics]
    if upload is not None:
        command += ["-H", "Content-Type: application/octet-stream", "-H", "Expect:",
                    "--data-binary", "@" + str(upload), "https://speed.cloudflare.com/__up"]
    else:
        command += ["https://speed.cloudflare.com/__down?bytes=" + str(download_bytes)]
    value = json.loads(subprocess.check_output(command, encoding="utf-8", stderr=subprocess.PIPE, timeout=65))
    expected = upload.stat().st_size if upload is not None else download_bytes
    actual = value["uploaded"] if upload is not None else value["downloaded"]
    if not 200 <= value["code"] < 300 or actual != expected:
        raise RuntimeError("Передача завершилась не полностью")
    if upload is None and destination.stat().st_size != expected:
        raise RuntimeError("Размер принятого файла не совпадает")
    if value["seconds"] <= 0:
        raise RuntimeError("Некорректная длительность измерения")
    return {"completed_bytes": expected, "seconds": value["seconds"],
            "first_byte_seconds": value["first_byte"],
            "mbit_per_second": round(expected * 8 / value["seconds"] / 1_000_000, 3)}


def sample(root, alias, cipher, download_bytes, upload_bytes, transport="https"):
    c = load(root)
    c["ssh_alias"], c["ssh_cipher"] = alias, cipher
    p = profile(alias)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        c["forward_port"] = listener.getsockname()[1]
    command = ssh_command(c, "trial", p)
    if transport == "stream":
        command = streamcheck.command(command, download_bytes, upload_bytes)
    process = subprocess.Popen(command, stdin=subprocess.PIPE if transport == "stream" else subprocess.DEVNULL,
                               stdout=subprocess.PIPE if transport == "stream" else subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, bufsize=0)
    try:
        deadline = time.monotonic() + c["connect_timeout"] + 2
        while time.monotonic() < deadline and process.poll() is None:
            if greeting(c["forward_port"]):
                break
            time.sleep(0.1)
        if process.poll() is not None or not greeting(c["forward_port"]):
            raise RuntimeError("SSH не открыл тестовый порт")
        ip = subprocess.check_output(["/usr/bin/curl", "--noproxy", "", "--fail", "--silent", "--show-error",
                                      "--connect-timeout", "10", "--max-time", "20", "--socks5-hostname",
                                      f"127.0.0.1:{c['forward_port']}", "https://api.ipify.org"],
                                     encoding="utf-8", stderr=subprocess.PIPE, timeout=25).strip()
        ipaddress.ip_address(ip)
        if ip != p["hostname"][0]:
            raise RuntimeError("Внешний IP не совпал с выбранным SSH-сервером")
        if transport == "stream":
            return {"status": "ok", "external_ip": ip,
                    **streamcheck.transfer(process, download_bytes, upload_bytes)}
        with tempfile.TemporaryDirectory(prefix="measure-", dir=directory(root)) as name:
            folder = Path(name)
            download = curl(c["forward_port"], folder / "download", download_bytes=download_bytes)
            upload_file = folder / "upload"
            upload_file.write_bytes(os.urandom(upload_bytes))
            upload = curl(c["forward_port"], folder / "response", upload=upload_file)
        return {"status": "ok", "external_ip": ip, "download": download, "upload": upload}
    finally:
        terminate([process])
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


def run(root, aliases, ciphers, repeats, download_mib, upload_mib, transport="https"):
    """Измерить завершенные передачи без изменения постоянной конфигурации.

    Parameters
    ----------
    root : Path
        Каталог проекта.
    aliases : list[str]
        Существующие SSH-алиасы пользователя.
    ciphers : list[str]
        Штатные шифры OpenSSH или default.
    repeats : int
        Число проходов с чередованием порядка кандидатов.
    download_mib : int
        Объем каждого скачивания в МиБ.
    upload_mib : int
        Объем каждой отправки в МиБ.
    transport : str
        https для интернет-запросов либо stream для потока Mac/VPS.

    Returns
    -------
    dict
        Результаты всех попыток, медианы и путь отчета.
    """
    if not aliases or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", a) for a in aliases):
        raise ValueError("Для замера нужны корректные SSH-алиасы")
    if not ciphers or any(c not in CIPHERS for c in ciphers):
        raise ValueError("Неподдерживаемый шифр")
    if transport not in ("https", "stream"):
        raise ValueError("Неподдерживаемый вид измерения")
    if not 1 <= repeats <= 5 or not 1 <= download_mib <= 32 or not 1 <= upload_mib <= 8:
        raise ValueError("Пределы замера: 1-5 повторов, загрузка 1-32 МиБ, отдача 1-8 МиБ")
    report = {"created_utc": datetime.now(timezone.utc).isoformat(),
              "transport": transport,
              "underlay": "Действующее сетевое подключение Mac, включая активный VPN",
              "routes_changed": False, "settings_changed": False,
              "download_mib": download_mib, "upload_mib": upload_mib, "samples": []}
    reports = root / "reports"
    reports.mkdir(exist_ok=True)
    target = reports / (datetime.now(timezone.utc).strftime("benchmark-%Y%m%dT%H%M%S-%fZ.json"))
    candidates = [(a, c) for a in dict.fromkeys(aliases) for c in dict.fromkeys(ciphers)]
    for repeat in range(repeats):
        order = candidates if repeat % 2 == 0 else list(reversed(candidates))
        for alias, cipher in order:
            print(f"Замер {repeat + 1}/{repeats}: {alias}, {cipher}", flush=True)
            record = {"alias": alias, "cipher": cipher, "repeat": repeat + 1}
            try:
                record.update(sample(root, alias, cipher, download_mib * 1048576, upload_mib * 1048576, transport))
                print(f"  IP {record['external_ip']}; загрузка {record['download']['mbit_per_second']} Мбит/с; "
                      f"отдача {record['upload']['mbit_per_second']} Мбит/с", flush=True)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                record.update(status="failed", error_type=type(error).__name__)
                if isinstance(error, subprocess.CalledProcessError):
                    record["exit_code"] = error.returncode
                    try:
                        record["http_code"] = json.loads(error.output)["code"]
                    except (ValueError, TypeError, KeyError):
                        pass
                print("  Не завершено: " + type(error).__name__ +
                      (f"; HTTP {record['http_code']}" if "http_code" in record else ""), flush=True)
            report["samples"].append(record)
            atomic(target, report)
    medians = []
    for alias, cipher in candidates:
        values = [v for v in report["samples"] if v["alias"] == alias and v["cipher"] == cipher and v["status"] == "ok"]
        if values:
            medians.append({"alias": alias, "cipher": cipher, "successful": len(values), "attempts": repeats,
                            "download_mbit": statistics.median(v["download"]["mbit_per_second"] for v in values),
                            "upload_mbit": statistics.median(v["upload"]["mbit_per_second"] for v in values)})
    report["medians"] = medians
    report["all_transfers_complete"] = all(s["status"] == "ok" for s in report["samples"])
    atomic(target, report)
    return {"report": str(target), "medians": medians, "settings_changed": False,
            "all_transfers_complete": report["all_transfers_complete"]}
