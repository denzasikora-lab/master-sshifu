#!/usr/bin/env python3
"""Установка закрепленного sing-box с проверкой архива до распаковки."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def target_platform():
    system = platform.system().lower()
    machine = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(platform.machine().lower())
    if system not in ('darwin', 'linux') or machine is None:
        raise RuntimeError('Поддерживаются macOS/Linux на arm64 и amd64')
    return system + '-' + machine


def extract_verified(archive, expected_sha256, target):
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError('SHA256 архива не совпал; установка отменена')
    with tarfile.open(archive, 'r:gz') as bundle:
        members = [m for m in bundle.getmembers() if Path(m.name).name == 'sing-box']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size < 268435456:
            raise RuntimeError('В архиве нет единственного обычного бинарного файла')
        member = bundle.extractfile(members[0])
        descriptor, name = tempfile.mkstemp(prefix='.sing-box-', dir=target.parent)
        try:
            with member, os.fdopen(descriptor, 'wb') as output:
                shutil.copyfileobj(member, output)
                output.flush()
                os.fsync(output.fileno())
            Path(name).chmod(0o755)
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def main():
    selected = target_platform()
    if selected.startswith('darwin') and os.geteuid() == 0:
        raise RuntimeError('На Mac установите зависимость от обычного пользователя, без sudo')
    manifest = json.loads((ROOT / 'vendor/releases.json').read_text(encoding='utf-8'))
    version = manifest['version']
    expected = manifest['assets'][selected]
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-{selected}.tar.gz'
    target = ROOT / 'vendor/sing-box'
    proof = ROOT / 'vendor/provenance.json'
    if target.exists() and proof.exists():
        previous = json.loads(proof.read_text(encoding='utf-8'))
        if (previous.get('platform') == selected and previous.get('archive_sha256') == expected and
                previous.get('binary_sha256') == hashlib.sha256(target.read_bytes()).hexdigest()):
            print('sing-box уже установлен и проверен: ' + version, flush=True)
            return
    print('Загрузка sing-box ' + version + ' для ' + selected, flush=True)
    with tempfile.TemporaryDirectory(prefix='sshifu-download-') as name:
        archive = Path(name) / 'release.tar.gz'
        request = urllib.request.Request(url, headers={'User-Agent': 'Master-SSHifu'})
        with urllib.request.urlopen(request, timeout=45) as response, archive.open('wb') as output:
            total = 0
            while True:
                block = response.read(1048576)
                if not block:
                    break
                total += len(block)
                if total > 134217728:
                    raise RuntimeError('Архив превысил допустимый размер')
                output.write(block)
        extract_verified(archive, expected, target)
    first = subprocess.check_output([str(target), 'version'], text=True, encoding='utf-8', timeout=10).splitlines()[0]
    if first != 'sing-box version ' + version:
        raise RuntimeError('Версия установленного файла отличается от закрепленной')
    value = {'version': version, 'platform': selected, 'url': url,
             'archive_sha256': expected, 'binary_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    proof.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('SHA256 и версия подтверждены. Установлено: ' + str(target), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Ошибка установки: ' + str(error))
