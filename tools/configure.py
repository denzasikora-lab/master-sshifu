#!/usr/bin/env python3
"""Создание личной конфигурации клиента без изменения сети."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sshvpn.config import load


def main():
    parser = argparse.ArgumentParser(description='Личные параметры Master SSHifu')
    parser.add_argument('--ssh-alias', default='master-sshifu')
    parser.add_argument('--interface', required=True)
    parser.add_argument('--backend-ready', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'config.json'
    value = json.loads((path if path.exists() else ROOT / 'config.example.json').read_text(encoding='utf-8'))
    value.update(ssh_alias=args.ssh_alias, physical_interface=args.interface)
    if args.backend_ready:
        value['backend_ready'] = True
    # Проверяем тем же валидатором до замены рабочей конфигурации.
    import tempfile
    with tempfile.TemporaryDirectory() as name:
        temporary = Path(name)
        (temporary / 'config.json').write_text(json.dumps(value), encoding='utf-8')
        load(temporary)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    path.chmod(0o600)
    print('Личная конфигурация сохранена: ' + str(path))


if __name__ == '__main__':
    main()
