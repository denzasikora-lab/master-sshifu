#!/usr/bin/env python3
"""Создание ярлыков Terminal на рабочем столе без запуска VPN."""

import argparse
import os
from pathlib import Path
import shlex
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MARKER = '# Ярлык Master SSHifu, созданный tools/create_shortcuts.py.'
ACTIONS = {
    'Включить': 'exec "$PWD/sshifu"',
    'Выключить': 'exec "$PWD/sshifu" stop',
    'Установить или обновить': 'exec /usr/bin/sudo "$PWD/.venv/bin/python" "$PWD/tools/install_launcher.py"',
    'Диагностика': 'exec "$PWD/.venv/bin/python" "$PWD/vpn.py" diagnose',
}


def create(root, desktop):
    """Создать ярлыки с фиксированными командами и абсолютным каталогом проекта.

    Parameters
    ----------
    root : pathlib.Path
        Корневой каталог рабочего клона.
    desktop : pathlib.Path
        Существующий рабочий стол пользователя.

    Returns
    -------
    list[pathlib.Path]
        Пути созданных или обновленных ярлыков.
    """
    if os.geteuid() == 0:
        raise RuntimeError('Создавайте ярлыки от обычного пользователя, без sudo')
    root = root.resolve(strict=True)
    desktop = desktop.expanduser().resolve(strict=True)
    if not desktop.is_dir():
        raise RuntimeError('Рабочий стол должен быть каталогом')
    shortcuts = [(desktop / ('Master SSHifu - ' + name + '.command'),
        '#!/bin/zsh\n' + MARKER + '\ncd -- ' + shlex.quote(str(root)) + ' || exit 1\n' + action + '\n')
        for name, action in ACTIONS.items()]
    for path, _ in shortcuts:
        if path.is_symlink() or (path.exists() and (not path.is_file() or
                MARKER not in path.read_text(encoding='utf-8'))):
            raise RuntimeError('Не заменяю посторонний файл: ' + str(path))
    for path, text in shortcuts:
        descriptor, temporary = tempfile.mkstemp(prefix='.sshifu-shortcut-', dir=desktop)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(text)
            os.chmod(temporary, 0o755)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return [path for path, _ in shortcuts]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Ярлыки Master SSHifu на рабочем столе')
    parser.add_argument('--desktop', type=Path, default=Path.home() / 'Desktop', help='Каталог рабочего стола')
    args = parser.parse_args()
    try:
        for path in create(ROOT, args.desktop):
            print('Создан ярлык: ' + path.name, flush=True)
    except (OSError, RuntimeError) as error:
        raise SystemExit('Ошибка создания ярлыков: ' + str(error))
