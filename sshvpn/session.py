"""Постоянное подключение с ручным переходом без начальных веб-проб."""

import fcntl
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

from . import PROJECT_NAME, protected, system
from .config import load
from .console import show
from .runtime import GuardedProcess, atomic, greeting, status, terminate, log_tail

REPORT = Path('/private/var/run/ssh-split-session.json')
LOG = Path('/private/var/run/ssh-split-session.log')


def healthy(expected, pulse):
    for endpoint in ('https://api.ipify.org', 'https://ipv4.icanhazip.com'):
        pulse()
        started = time.monotonic()
        result = {'event': 'health_probe', 'time': time.time(), 'endpoint': endpoint}
        try:
            value = system.command(['/usr/bin/curl', '--noproxy', '*', '-4fsS',
                '--connect-timeout', '3', '--max-time', '5', endpoint], timeout=6).strip()
            ok = str(ipaddress.IPv4Address(value)) == expected
            result.update(ok=ok, reason=None if ok else 'Внешний IP не совпал с сервером')
            return ok
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            result.update(ok=False, error_type=type(error).__name__, error=str(error)[:1000])
        finally:
            result['seconds'] = round(time.monotonic() - started, 3)
            logging.getLogger('sshvpn.session').info(json.dumps(result, ensure_ascii=False))
    return False


def emergency_report(journal):
    # Защитник завершает открытый отчет даже после SIGKILL основного процесса.
    state = system.current()
    if state.get('journal') != str(journal):
        return
    root = Path(__file__).resolve().parent.parent
    try:
        report = json.loads(REPORT.read_text(encoding='utf-8'))
        if report.get('state', {}).get('journal') != str(journal):
            return
        try:
            protected.wait_cleanup(state, ports=load(root))
            report['cleanup'] = protected.cleanup_snapshot(state, load(root))
        except Exception as error:
            report['cleanup_error'] = str(error)
        report.update(phase='interrupted', finished=time.time(),
                      error='Локальный защитник завершил процесс по таймеру или потере активности',
                      failure_phase=state.get('phase'),
                      diagnostics={name: log_tail(journal.parent / name) for name in
                          ('ssh.log', 'tun.log', 'dns.log', 'watchdog-events.json')})
        atomic(REPORT, report)
        REPORT.chmod(0o644)
    except (OSError, ValueError):
        pass


def reconnect(previous, command, username, log_path, config, pulse, requested):
    terminate([previous])
    child = None
    delivered = False
    try:
        for attempt in range(config['max_restarts']):
            end = time.monotonic() + min(2 ** attempt, 16)
            while time.monotonic() < end:
                if requested():
                    raise InterruptedError('Остановка во время восстановления SSH')
                pulse()
                time.sleep(0.2)
            # Ошибки предыдущих попыток сохраняются в пределах текущего сеанса.
            with log_path.open('a', encoding='utf-8') as log:
                log.write('\nПопытка восстановления SSH: ' + str(attempt + 1) + '\n')
                log.flush()
                child = GuardedProcess(['/usr/bin/sudo', '-n', '-u', username, '--', *command], stderr=log)
            end = time.monotonic() + config['connect_timeout'] + 2
            while child.poll() is None and time.monotonic() < end:
                if requested():
                    raise InterruptedError('Остановка во время восстановления SSH')
                pulse()
                if greeting(config['forward_port']):
                    delivered = True
                    return child
                time.sleep(0.2)
            terminate([child])
        raise RuntimeError('SSH не восстановился за ограниченное число попыток: выполняется откат')
    finally:
        if child is not None and not delivered:
            terminate([child])


def connect(root):
    if not sys.stdin.isatty():
        raise RuntimeError('Запустите connect в обычном терминале; остановка выполняется через Ctrl+C')
    if os.geteuid() != 0 or int(os.environ.get('SUDO_UID', '0')) == 0:
        raise RuntimeError('Для создания TUN запустите connect через sudo из учетной записи владельца проекта')
    from .installation import owner_uid
    if owner_uid(root) != int(os.environ['SUDO_UID']):
        raise RuntimeError('Владелец проекта не совпадает с SUDO_UID')
    descriptor = os.open(protected.CHECK_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if system.current()['running'] or status(root)['running']:
            raise RuntimeError('Другой сеанс проекта уже работает')
        return _connect_locked(root)
    finally:
        os.close(descriptor)


def _connect_locked(root):
    config = load(root)
    report = {'project': PROJECT_NAME, 'phase': 'starting', 'started': time.time(), 'persistent': False,
              'startup_web_probes': False, 'confirmation_required': False,
              'amnezia_restart_attempted': False, 'manual_reconnect_required': True}
    handler = RotatingFileHandler(LOG, maxBytes=1048576, backupCount=3, encoding='utf-8')
    LOG.chmod(0o644)
    logger = logging.getLogger('sshvpn.session')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)
    last_phase = None
    last_health_check = None
    was_ready = False

    def save():
        atomic(REPORT, report)
        REPORT.chmod(0o644)

    def changed(state):
        nonlocal last_phase, last_health_check, was_ready
        report.update(phase=state['phase'], state=state,
                      persistent=state.get('persistent', False))
        save()
        if state['phase'] != last_phase or state.get('last_health_check') != last_health_check:
            logger.info(json.dumps({'time': time.time(), 'run_id': state['run_id'],
                'pid': state['pid'], 'child_guard_pids': state.get('child_guard_pids'),
                'phase': state['phase'], 'reconnects': state.get('reconnects', 0),
                'failure_phase': state.get('failure_phase'), 'child_exit_codes': state.get('child_exit_codes'),
                'cleanup_seconds': state.get('cleanup_seconds'),
                'rollback_conflicts': state.get('rollback_conflicts'),
                'health_checks': state.get('health_checks'),
                'consecutive_health_failures': state.get('consecutive_health_failures'),
                'diagnostics': state.get('diagnostics'),
                'reason': state.get('reason')}, ensure_ascii=False))
            last_health_check = state.get('last_health_check')
        if state['phase'] != last_phase:
            if state['phase'] == 'ready' and state.get('persistent'):
                was_ready = True
                show('включено.', 'success')
            elif state['phase'] == 'reconnecting':
                show('переподключение...', 'warning')
            last_phase = state['phase']

    save()
    show('подготовка...')
    try:
        system.run(root, duration=0, interactive=True, on_state=changed)
    except system.VPNConflictError as error:
        report.update(phase='blocked_by_vpn', error=str(error), network_changed=False,
            manual_reconnect_required=False,
            other_vpn={'interfaces': error.interfaces, 'clients': error.clients},
            cleanup={'verified': True, 'not_started': True})
    except (Exception, KeyboardInterrupt) as error:
        report.update(phase='failed', error=str(error) or type(error).__name__,
                      traceback=traceback.format_exc()[-12000:])
    finally:
        state = system.current()
        if not report.get('other_vpn') and state.get('pid') == os.getpid() and state.get('journal'):
            report['state'] = state
            try:
                protected.wait_cleanup(state, ports=config)
                report['cleanup'] = protected.cleanup_snapshot(state, config)
            except Exception as error:
                report['cleanup_error'] = str(error)
        report['finished'] = time.time()
        if not report.get('error'):
            report['phase'] = 'stopped' if report.get('cleanup', {}).get('verified') else 'rollback_conflict'
        save()
        logger.info(json.dumps({'time': time.time(), 'phase': report['phase'],
            'error': report.get('error'), 'cleanup_error': report.get('cleanup_error'),
            'traceback': report.get('traceback'),
            'cleanup_verified': report.get('cleanup', {}).get('verified', False)}, ensure_ascii=False))
        logger.removeHandler(handler)
        handler.close()
        tone = 'error'
        if report.get('other_vpn'):
            names = ', '.join(report['other_vpn']['clients'] or report['other_vpn']['interfaces'])
            message = 'обнаружен другой VPN: ' + names + '. Не включено.'
            tone = 'warning'
        elif not report.get('cleanup', {}).get('verified'):
            message = 'ошибка очистки.'
        elif report.get('error'):
            message = 'связь потеряна.' if was_ready else 'не удалось включить.'
        else:
            message = 'выключено.'
            tone = 'muted'
        show(message, tone)
    return report
