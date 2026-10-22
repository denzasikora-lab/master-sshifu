"""Замер настоящей передачи Mac/VPS с проверкой длины и SHA256."""

import hashlib
import json
import os
import select
import shlex
import time

REMOTE = """import hashlib,json,os,sys
download,upload=map(int,sys.argv[1:3])
payload=os.urandom(download)
writer=sys.stdout.buffer
reader=sys.stdin.buffer
writer.write((json.dumps({'length':download,'sha256':hashlib.sha256(payload).hexdigest()})+'\\n').encode())
writer.flush()
if reader.read(1)!=b'D':
    raise SystemExit(2)
writer.write(payload)
writer.flush()
received=0
digest=hashlib.sha256()
while received<upload:
    part=reader.read(min(65536,upload-received))
    if not part:
        raise SystemExit(3)
    digest.update(part)
    received+=len(part)
writer.write((json.dumps({'length':received,'sha256':digest.hexdigest()})+'\\n').encode())
writer.flush()
"""


def command(base, download_bytes, upload_bytes):
    args = [arg for arg in base if arg not in ("-N", "-n")]
    return args + ["python3 -c " + shlex.quote(REMOTE) + f" {download_bytes} {upload_bytes}"]


def receive(stream, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError("Истек срок приема SSH-потока")
        chunk = os.read(stream.fileno(), min(size - len(data), 65536))
        if not chunk:
            raise ConnectionError("SSH-поток оборван до завершения")
        data.extend(chunk)
    return bytes(data)


def line(stream, deadline):
    value = bytearray()
    while len(value) < 4096:
        char = receive(stream, 1, deadline)
        if char == b"\n":
            return json.loads(value)
        value.extend(char)
    raise ValueError("Некорректный заголовок SSH-потока")


def send(stream, data, deadline):
    os.set_blocking(stream.fileno(), False)
    position = 0
    while position < len(data):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [stream], [], remaining)[1]:
            raise TimeoutError("Истек срок отправки SSH-потока")
        try:
            position += os.write(stream.fileno(), data[position:position + 65536])
        except BlockingIOError:
            continue


def transfer(process, download_bytes, upload_bytes):
    deadline = time.monotonic() + 120
    header = line(process.stdout, deadline)
    if header.get("length") != download_bytes:
        raise ValueError("Сервер объявил неверный размер")
    started = time.monotonic()
    send(process.stdin, b"D", deadline)
    payload = receive(process.stdout, download_bytes, deadline)
    download_seconds = time.monotonic() - started
    if hashlib.sha256(payload).hexdigest() != header["sha256"]:
        raise ValueError("Хеш скачанного потока не совпал")
    upload = os.urandom(upload_bytes)
    expected = hashlib.sha256(upload).hexdigest()
    started = time.monotonic()
    send(process.stdin, upload, deadline)
    response = line(process.stdout, deadline)
    upload_seconds = time.monotonic() - started
    if response.get("length") != upload_bytes or response.get("sha256") != expected:
        raise ValueError("Сервер не подтвердил размер и хеш отправленного потока")
    if process.wait(timeout=5) != 0:
        raise RuntimeError("SSH завершился с ошибкой")
    return {direction: {"completed_bytes": size, "seconds": round(seconds, 6), "sha256_verified": True,
                        "mbit_per_second": round(size * 8 / seconds / 1_000_000, 3)}
            for direction, size, seconds in (("download", download_bytes, download_seconds),
                                             ("upload", upload_bytes, upload_seconds))}
