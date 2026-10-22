"""Сбор локальной диагностики без запросов в интернет и без изменения сети."""

from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import sys

from . import PROJECT_NAME
from .runtime import atomic, directory


def read_local(path, limit=32768):
    """Прочитать конец локального файла без отказа всей диагностики.

    Parameters
    ----------
    path : pathlib.Path
        Файл журнала или отчета.
    limit : int
        Максимальный размер читаемого фрагмента в байтах.

    Returns
    -------
    str or dict or None
        Фрагмент, описание ошибки чтения или отсутствие файла.
    """
    try:
        with path.open('rb') as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - limit))
            return stream.read(limit).decode('utf-8', errors='replace')
    except FileNotFoundError:
        return None
    except OSError as error:
        return {'error': str(error)}


def collect(root, target=None):
    """Сохранить ограниченный набор журналов, не читая ключи и конфигурацию SSH.

    Parameters
    ----------
    root : pathlib.Path
        Корневой каталог проекта.
    target : str or None
        Явный путь результата или автоматическое имя в .runtime.

    Returns
    -------
    dict
        Путь результата и признаки отсутствия сетевых действий.
    """
    report = {'project': PROJECT_NAME, 'created_utc': datetime.now(timezone.utc).isoformat(),
              'python': sys.version, 'platform': ' '.join((platform.system(), platform.release(), platform.machine())),
              'files': {},
              'network_changed': False, 'internet_requests': False}
    paths = [Path('/private/var/run/ssh-split-session.json'),
             Path('/private/var/run/ssh-split-session.log'), Path('/private/var/run/ssh-split-vpn.json'),
             Path('/private/var/run/ssh-split-manual-check.json'),
             Path('/private/var/run/ssh-split-protected-check.json'),
             Path('/private/var/run/ssh-split-cleanup-audit.json')]
    paths += [root / '.runtime' / name for name in ('state.json', 'events.log', 'ssh.log', 'tun.log')]
    paths += [Path('/private/var/run/ssh-split-session.log.' + str(n)) for n in range(1, 4)]
    paths += [root / '.runtime' / ('events.log.' + str(n)) for n in (1, 2)]
    for path in paths:
        report['files'][str(path)] = read_local(path)
    path = Path(target).expanduser().resolve() if target else directory(root) / (
        'diagnostics-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.json')
    atomic(path, report)
    path.chmod(0o600)
    return {'report': str(path), 'network_changed': False, 'internet_requests': False}
