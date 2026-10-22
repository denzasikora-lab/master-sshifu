"""Офлайн-приемка с ручным отключением и возвратом исходного VPN."""

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import time

from . import protected, recovery, system
from .config import load
from .runtime import atomic, status

REPORT = Path('/private/var/run/ssh-split-manual-check.json')


def accepted(report, server_ip, now):
    """Проверить предыдущую ограниченную приемку перед ручным испытанием.

    Parameters
    ----------
    report : dict
        Системный отчет ограниченной приемки.
    server_ip : str
        Адрес выбранного SSH-сервера.
    now : float
        Текущее время Unix.

    Returns
    -------
    bool
        Подтверждены все этапы и свежесть отчета.
    """
    stages = report.get('stages', [])
    return (report.get('phase') == 'passed' and
            report.get('limited_route_recovery_verified') is True and
            0 <= now - report.get('finished', 0) <= 86400 and
            [stage.get('stage') for stage in stages] == ['kill', 'hang', 'traffic'] and
            all(stage.get('cleanup') == {'conflicts': []} for stage in stages) and
            (stages[-1].get('probe') or {}).get('ssh_external_ip') == server_ip and
            (stages[-1].get('probe') or {}).get('ru_direct_log_verified') is True)


def traffic(config, scratch, server_ip, pulse, progress):
    result = {'system_requests': True, 'youtube_playback_verified': False,
              'speedtest_completed': False}
    for host in ('api.ipify.org', 'yandex.ru', 'checkip.amazonaws.com',
                 'www.youtube.com', 'www.speedtest.net'):
        pulse()
        value, target = protected.fetch(host, '/', scratch)
        result[host] = value
        progress(result)
        if not 200 <= value['http_status'] < (400 if host == 'yandex.ru' else 300):
            raise RuntimeError('Не прошел системный запрос: ' + host)
        if host == 'api.ipify.org':
            ip = str(ipaddress.IPv4Address(target.read_text(encoding='utf-8').strip()))
            if ip != server_ip:
                raise RuntimeError('Системный выход не совпал с SSH-сервером')
            result['ssh_external_ip'] = ip
        if host == 'checkip.amazonaws.com':
            ip = str(ipaddress.IPv4Address(target.read_text(encoding='utf-8').strip()))
            if ip == server_ip:
                raise RuntimeError('Прямой выход совпал с SSH-сервером')
            result['direct_external_ip'] = ip
        if host == 'yandex.ru':
            deadline = time.monotonic() + 2
            while True:
                log = (scratch / 'engine.log').read_text(encoding='utf-8')
                result['ru_direct_log_verified'] = any('outbound/direct[direct]' in line and
                    'yandex.ru:443' in line for line in log.splitlines())
                if result['ru_direct_log_verified'] or time.monotonic() >= deadline:
                    break
                pulse()
                time.sleep(0.05)
            if not result['ru_direct_log_verified']:
                raise RuntimeError('Прямой маршрут ru не подтвержден журналом')
        progress(result)
    pulse()
    value, _ = protected.fetch('speed.cloudflare.com', '/__down?bytes=8388608', scratch)
    if value['http_status'] != 200 or value['bytes'] != 8388608:
        raise RuntimeError('Системная загрузка не завершена')
    value['mbit_per_second'] = round(value['bytes'] * 8 / value['seconds'] / 1000000, 2)
    result['download'] = value
    progress(result)
    pulse()
    return result


def check(root, duration):
    if not 180 <= duration <= 600:
        raise ValueError('Продолжительность должна быть от 180 до 600 секунд')
    if os.geteuid() != 0 or int(os.environ.get('SUDO_UID', '0')) == 0:
        raise RuntimeError('Запустите manual-check через sudo при включенной Amnezia')
    user = pwd.getpwuid(int(os.environ['SUDO_UID']))
    if root.stat().st_uid != user.pw_uid:
        raise RuntimeError('Владелец проекта не совпадает с SUDO_UID')
    descriptor = os.open(protected.CHECK_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return check_locked(root, duration, user)
    finally:
        os.close(descriptor)


def check_locked(root, duration, user):
    if system.current()['running'] or status(root)['running']:
        raise RuntimeError('Другой сеанс проекта уже работает')
    config = load(root)
    baseline = protected.baseline_routes(system.MacRoutes())
    prefs = Path(user.pw_dir) / 'Library/Preferences/org.amneziavpn.AmneziaVPN.plist'
    saved_profile = recovery.preferences(prefs)
    saved_dns = system.command(['/usr/sbin/scutil', '--dns'])
    process_ids = recovery.pids()
    if not process_ids:
        raise RuntimeError('Amnezia не найдена; сначала верните исходное подключение')
    previous = json.loads(protected.REPORT.read_text(encoding='utf-8'))
    clean_env = {'HOME': user.pw_dir, 'USER': user.pw_name, 'LOGNAME': user.pw_name,
                 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'PYTHONIOENCODING': 'utf-8'}
    exported = json.loads(system.command([sys.executable, str(root / 'vpn.py'), '_export-system'],
        user=user.pw_uid, group=user.pw_gid,
        extra_groups=os.getgrouplist(user.pw_name, user.pw_gid), env=clean_env))
    if not accepted(previous, exported['server_ip'], time.time()):
        raise RuntimeError('Нет свежей успешной ограниченной приемки выбранного сервера')
    if recovery.ipv4() != previous['expected_ip']:
        raise RuntimeError('Текущее подключение отличается от принятой исходной Amnezia')
    report = {'phase': 'starting', 'started': time.time(), 'duration': duration,
              'manual_reconnect_required': True, 'amnezia_restart_attempted': False,
              'baseline_routes': baseline, 'expected_ip': exported['server_ip'],
              'youtube_playback_verified': False, 'speedtest_completed': False}

    def save():
        atomic(REPORT, report)
        REPORT.chmod(0o644)

    save()
    print('Amnezia пока оставьте включенной. Дождитесь сообщения об отключении.', flush=True)
    log_path = Path('/private/var/run/ssh-split-manual-check.log')
    fd = os.open(log_path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    child = None
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as log:
            child = subprocess.Popen([sys.executable, str(root / 'vpn.py'), '_manual-worker',
                                      '--duration', str(duration)], stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline, last_phase = time.monotonic() + duration + 390, None
            while child.poll() is None:
                if time.monotonic() > deadline:
                    child.kill()
                    raise RuntimeError('Исполнитель превысил общий срок')
                state = system.current()
                if state.get('pid') == child.pid:
                    report.update(phase=state['phase'], state=state)
                    save()
                    if state['phase'] != last_phase:
                        if state['phase'] == 'awaiting_disconnect':
                            print('Таймер включен. Теперь вручную отключите Amnezia. Happ не включайте. '
                                  'У вас 120 секунд; чат может потерять связь.', flush=True)
                        elif state['phase'] == 'ready':
                            print('Наш VPN готов. Откройте YouTube: видео 1080p на 1-2 минуты. '
                                  'Затем speedtest.net: GO, дождитесь загрузки и отдачи, сохраните результат. '
                                  f'Через {duration} секунд наш VPN остановится. Затем включите Amnezia вручную.', flush=True)
                        elif state['phase'] == 'checking':
                            print('Идут автоматические проверки системного IP, ru и HTTPS.', flush=True)
                        last_phase = state['phase']
                time.sleep(0.5)
            state = system.current()
            if state.get('pid') != child.pid:
                raise RuntimeError('Исполнитель не создал собственный системный сеанс')
            report['state'] = state
            report['worker_returncode'] = child.returncode
            report['automatic_checks_passed'] = (child.returncode == 0 and
                bool(state.get('probe', {}).get('ru_direct_log_verified')) and
                state.get('probe', {}).get('ssh_external_ip') == exported['server_ip'])
            save()
            report['cleanup'] = protected.wait_cleanup(state, ports=config)
            # После ручного отключения Amnezia ее DNS может штатно исчезнуть.
            report['dns_matches_before_disconnect'] = system.command(['/usr/sbin/scutil', '--dns']) == saved_dns
            report['profile_unchanged'] = recovery.preferences(prefs) == saved_profile
            report['amnezia_process_preserved'] = recovery.pids() == process_ids
            report['phase'] = 'awaiting_manual_reconnect' if report['automatic_checks_passed'] else 'failed'
            if not report['profile_unchanged'] or not report['amnezia_process_preserved']:
                report['phase'] = 'failed'
    except BaseException as error:
        report.update(phase='failed', reason=str(error))
        raise
    finally:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if child is not None and 'cleanup' not in report:
            state = system.current()
            if state.get('pid') == child.pid and state.get('journal'):
                report['state'] = state
                try:
                    report['cleanup'] = protected.wait_cleanup(state, ports=config)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    report['cleanup_error'] = str(error)
        if child is not None:
            state = system.current()
            if state.get('pid') == child.pid and state.get('journal'):
                try:
                    # Открытый отчет содержит всю диагностику очистки без отдельного sudo.
                    report['cleanup_details'] = protected.cleanup_snapshot(state, config)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    report['cleanup_details_error'] = str(error)
        report['finished'] = time.time()
        save()
        cleanup = 'Очистка подтверждена.' if report.get('cleanup') == {'conflicts': []} else 'Проверьте ошибку очистки в отчете.'
        print('Испытание закончено. ' + cleanup + ' Включите Amnezia вручную. '
              'Отчет: ' + str(REPORT), flush=True)
    return report
