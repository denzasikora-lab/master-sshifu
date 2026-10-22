#!/usr/bin/env python3
"""Однократная установка ограниченного запуска без пароля для текущего владельца."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sshvpn.installation import install


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Системная копия Master SSHifu без повторного пароля')
    parser.add_argument('--remove', action='store_true', help='Удалить разрешение и системную копию')
    args = parser.parse_args()
    try:
        install(ROOT, remove=args.remove)
    except Exception as error:
        raise SystemExit('Ошибка установки: ' + str(error))
