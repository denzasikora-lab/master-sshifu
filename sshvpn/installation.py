"""Установка отдельной защищенной копии для запуска VPN без повторного пароля."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import tempfile

INSTALL_ROOT = Path('/Library/PrivilegedHelperTools/master-sshifu')
POLICY = Path('/private/etc/sudoers.d/master-sshifu')
COMMANDS = ('connect', 'stop', 'status', 'check')


def secure_path(path):
    """Проверить владение root и отсутствие записи для остальных учетных записей.

    Parameters
    ----------
    path : pathlib.Path
        Существующий файл или каталог с проверкой всех родителей.

    Returns
    -------
    pathlib.Path
        Разрешенный абсолютный путь.
    """
    resolved = path.resolve(strict=True)
    for item in (resolved, *resolved.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Небезопасные права системного пути: ' + str(item))
    return resolved


def owner_uid(root):
    if root.resolve() != INSTALL_ROOT:
        return root.stat().st_uid
    secure_path(INSTALL_ROOT)
    marker = INSTALL_ROOT / 'installation.json'
    secure_path(marker)
    value = json.loads(marker.read_text(encoding='utf-8'))
    uid = value['owner_uid']
    if type(uid) is not int or uid <= 0:
        raise RuntimeError('Некорректный владелец системной установки')
    return uid


def system_python():
    # Python Apple не зависит от изменяемого пользователем окружения .venv.
    value = json.loads(subprocess.check_output(['/usr/bin/python3', '-I', '-S', '-B', '-c',
        'import json,sys,sysconfig;print(json.dumps([sys.executable,sysconfig.get_path("stdlib")]))'],
        text=True, encoding='utf-8', timeout=15))
    executable, library = (secure_path(Path(p)) for p in value)
    if not str(executable).startswith('/Library/Developer/CommandLineTools/'):
        raise RuntimeError('Нужен системный Python Apple из Command Line Tools')
    for base, dirs, files in os.walk(library):
        # -S исключает site-packages, они не нужны привилегированному исполнителю.
        dirs[:] = [d for d in dirs if d != 'site-packages']
        for name in dirs + files:
            secure_path(Path(base) / name)
    return str(executable)


def sudoers(username):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', username):
        raise ValueError('Некорректное имя учетной записи для sudoers')
    allowed = ', '.join(str(INSTALL_ROOT / 'launch') + ' ' + command for command in COMMANDS)
    return ('# Только фиксированные команды установленного Master SSHifu.\n'
            + username + ' ALL=(root) NOPASSWD: NOSETENV: ' + allowed + '\n')


def source_files(root):
    paths = [Path('vpn.py'), Path('config.json'), Path('vendor/sing-box'), Path('vendor/provenance.json')]
    paths += [p.relative_to(root) for p in sorted((root / 'sshvpn').glob('*.py'))]
    paths += [Path('rules') / name for name in ('direct-domains.txt', 'direct-cidrs.txt',
              'local-domains.txt', 'local-cidrs.txt') if (root / 'rules' / name).exists()]
    for path in paths:
        original = root / path
        if original.is_symlink() or not original.is_file() or not original.resolve().is_relative_to(root.resolve()):
            raise RuntimeError('Недопустимый файл установки: ' + str(path))
    return paths


def launch_text(executable):
    # Пути фиксируются во время административной установки, аргументы проверяет entry.
    import shlex
    return ('#!/bin/sh\nexec ' + shlex.quote(executable) + ' -I -S -B '
            + str(INSTALL_ROOT / 'entry.py') + ' "$@"\n')


ENTRY = '''"""Фиксированная точка входа установленной системной копии."""
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sshvpn.installation import installed_main
try:
    raise SystemExit(installed_main(sys.argv[1:]))
except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
    print('Master SSHifu: ' + str(error), file=sys.stderr)
    raise SystemExit(1)
'''


def installed_main(arguments):
    if len(arguments) != 1 or arguments[0] not in COMMANDS:
        raise RuntimeError('Разрешены только connect, stop, status и check без дополнительных аргументов')
    if os.geteuid() != 0 or int(os.environ.get('SUDO_UID', '0')) != owner_uid(INSTALL_ROOT):
        raise RuntimeError('Системная копия установлена для другой учетной записи')
    os.chdir(INSTALL_ROOT)
    # Служебным процессам не передается окружение пользовательского проекта.
    uid = str(owner_uid(INSTALL_ROOT))
    color = os.environ.get('NO_COLOR')
    term = os.environ.get('TERM', 'dumb')
    os.environ.clear()
    os.environ.update(HOME='/var/root', PATH='/usr/bin:/bin:/usr/sbin:/sbin',
                      SUDO_UID=uid, TERM=term, PYTHONIOENCODING='utf-8')
    if color is not None:
        os.environ['NO_COLOR'] = color
    from . import system
    from .config import load
    from .runtime import binary
    command = arguments[0]
    if command == 'check':
        load(INSTALL_ROOT)
        binary(INSTALL_ROOT)
        print(json.dumps({'installed': True, 'owner_uid': int(uid),
                          'network_changed': False, 'passwordless': True}, ensure_ascii=False))
        return 0
    if command == 'connect':
        from .session import connect
        descriptor = os.open('/private/var/run/master-sshifu-install.lock',
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            result = connect(INSTALL_ROOT)
        finally:
            os.close(descriptor)
        return 0 if result.get('cleanup', {}).get('verified') and not result.get('error') else 1
    state = system.current()
    if command == 'stop':
        if state.get('running') and state.get('owner_uid') != int(uid):
            raise RuntimeError('Активный сеанс принадлежит другой учетной записи')
        state = system.request_stop(INSTALL_ROOT)
    print(json.dumps(state, ensure_ascii=False, indent=2))
    return 0


def install(root, remove=False):
    if platform.system() != 'Darwin':
        raise RuntimeError('Системная установка поддерживается только на Mac')
    if os.geteuid() != 0:
        raise RuntimeError('Однократная установка требует sudo; повседневный запуск затем без пароля')
    uid = int(os.environ.get('SUDO_UID', '0'))
    if uid <= 0 or root.stat().st_uid != uid:
        raise RuntimeError('Запустите установку через sudo от владельца проекта')
    from .system import current
    if current().get('running'):
        raise RuntimeError('Сначала остановите действующий сеанс Master SSHifu')
    descriptor = os.open('/private/var/run/master-sshifu-install.lock',
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if current().get('running'):
            raise RuntimeError('Сначала остановите действующий сеанс Master SSHifu')
        if remove:
            if INSTALL_ROOT.exists() and owner_uid(INSTALL_ROOT) != uid:
                raise RuntimeError('Установка принадлежит другой учетной записи')
            POLICY.unlink(missing_ok=True)
            if INSTALL_ROOT.exists():
                shutil.rmtree(INSTALL_ROOT)
            print('Разрешение запуска без пароля и системная копия удалены.', flush=True)
            return
        _install_locked(root, uid)
    finally:
        os.close(descriptor)


def write_policy(content):
    descriptor, temporary = tempfile.mkstemp(prefix='.master-sshifu-policy-', dir=POLICY.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o440)
        os.replace(temporary, POLICY)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _install_locked(root, uid):
    from .config import load
    from .runtime import binary
    load(root)
    binary(root)
    executable = system_python()
    paths = source_files(root)
    if INSTALL_ROOT.exists() and owner_uid(INSTALL_ROOT) != uid:
        raise RuntimeError('Установка принадлежит другой учетной записи')
    for directory in (INSTALL_ROOT.parent, POLICY.parent):
        if not directory.exists():
            secure_path(directory.parent)
            directory.mkdir(mode=0o755)
        secure_path(directory)
    stage = Path(tempfile.mkdtemp(prefix='.master-sshifu-new-', dir=INSTALL_ROOT.parent))
    backup = INSTALL_ROOT.with_name('.master-sshifu-previous')
    if backup.exists():
        shutil.rmtree(stage)
        raise RuntimeError('Осталась резервная системная копия; сначала проверьте прошлую установку')
    previous_policy = POLICY.read_bytes() if POLICY.exists() else None
    published = False
    swapped = False
    candidate = stage / 'sudoers-candidate'
    try:
        stage.chmod(0o755)
        hashes = {}
        for relative in paths:
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            destination.parent.chmod(0o755)
            shutil.copyfile(root / relative, destination)
            destination.chmod(0o755 if relative == Path('vendor/sing-box') else 0o644)
            hashes[str(relative)] = hashlib.sha256(destination.read_bytes()).hexdigest()
        (stage / 'entry.py').write_text(ENTRY, encoding='utf-8')
        (stage / 'entry.py').chmod(0o644)
        (stage / 'launch').write_text(launch_text(executable), encoding='utf-8')
        (stage / 'launch').chmod(0o755)
        (stage / 'installation.json').write_text(json.dumps({'owner_uid': uid,
            'python': executable, 'sha256': hashes}, ensure_ascii=False, indent=2), encoding='utf-8')
        (stage / 'installation.json').chmod(0o644)
        candidate.write_text(sudoers(pwd.getpwuid(uid).pw_name), encoding='utf-8')
        candidate.chmod(0o440)
        subprocess.run(['/usr/sbin/visudo', '-cf', str(candidate)], check=True)
        subprocess.run([executable, '-I', '-S', '-B', str(stage / 'vpn.py'), 'server-config'],
                       check=True, stdout=subprocess.DEVNULL, timeout=15, cwd='/')
        policy_content = candidate.read_bytes()
        candidate.unlink()
        if INSTALL_ROOT.exists():
            INSTALL_ROOT.rename(backup)
        stage.rename(INSTALL_ROOT)
        swapped = True
        published = True
        write_policy(policy_content)
        subprocess.run(['/usr/sbin/visudo', '-c'], check=True)
        if backup.exists():
            shutil.rmtree(backup)
        print('Готово. Теперь можно запускать ./sshifu без пароля.', flush=True)
    except BaseException:
        if published:
            if previous_policy is None:
                POLICY.unlink(missing_ok=True)
            else:
                write_policy(previous_policy)
        if swapped and INSTALL_ROOT.exists():
            shutil.rmtree(INSTALL_ROOT)
        if backup.exists():
            backup.rename(INSTALL_ROOT)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
