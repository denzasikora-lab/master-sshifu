"""Локальные регрессионные и сетевые проверки без системного туннеля."""

import copy
import getpass
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import socket
import socketserver
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from sshvpn.config import client, load, server, write
from sshvpn.rules import Rules, domain
from sshvpn.routes import Journal, Route
from sshvpn.runtime import binary, greeting, status, stop, supervise
from sshvpn.transport import ssh_command
from sshvpn import benchmark, streamcheck
from sshvpn.system import canonical, dns_script, MacRoutes, parse_routes
from sshvpn import recovery
from sshvpn import protected

ROOT = Path(__file__).resolve().parent.parent


def port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def receive(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise ConnectionError("Соединение закрыто")
        data += part
    return data


def socks(port_number, target, target_port, command=1):
    stream = socket.create_connection(("127.0.0.1", port_number), timeout=3)
    stream.sendall(b"\x05\x01\x00")
    if receive(stream, 2) != b"\x05\x00":
        stream.close()
        raise ConnectionError("Ошибка SOCKS")
    host = target.encode("ascii")
    stream.sendall(bytes([5, command, 0, 3, len(host)]) + host + struct.pack("!H", target_port))
    response = receive(stream, 4)
    if response[1] != 0:
        stream.close()
        raise ConnectionError("Запрос отклонен")
    size = {1: 4, 4: 16}.get(response[3])
    if size is None:
        size = receive(stream, 1)[0]
    address = receive(stream, size)
    bound_port = struct.unpack("!H", receive(stream, 2))[0]
    return stream, (socket.inet_ntoa(address) if size == 4 else "127.0.0.1", bound_port)


def query(name, ident=1234):
    encoded = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\0"
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + encoded + struct.pack("!HH", 1, 1)


def udp_payload(packet):
    if packet[:3] != b"\0\0\0":
        raise ValueError("Некорректный UDP-ответ SOCKS")
    if packet[3] == 1:
        offset = 10
    elif packet[3] == 4:
        offset = 22
    elif packet[3] == 3:
        offset = 7 + packet[4]
    else:
        raise ValueError("Неизвестный тип адреса SOCKS")
    return packet[offset:]


class DNS:
    def __init__(self, ip):
        self.ip, self.names = ip, []
        self.port = port()
        owner = self

        def answer(data):
            offset, parts = 12, []
            while data[offset]:
                size = data[offset]
                parts.append(data[offset + 1:offset + size + 1].decode("ascii"))
                offset += size + 1
            owner.names.append(".".join(parts))
            question = data[12:offset + 5]
            return (data[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + question
                    + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(owner.ip))

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, stream = self.request
                stream.sendto(answer(data), self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    while True:
                        size = struct.unpack("!H", receive(self.request, 2))[0]
                        data = answer(receive(self.request, size))
                        self.request.sendall(struct.pack("!H", len(data)) + data)
                except (OSError, ConnectionError):
                    pass

        self.servers = [socketserver.ThreadingUDPServer(("127.0.0.1", self.port), UDP),
                        socketserver.ThreadingTCPServer(("127.0.0.1", self.port), TCP)]
        for item in self.servers:
            item.daemon_threads = True
            threading.Thread(target=item.serve_forever, daemon=True).start()

    def close(self):
        for item in self.servers:
            item.shutdown()
            item.server_close()


class Kernel:
    def __init__(self):
        self.routes = {}
        self.fail = False

    def get(self, prefix):
        return self.routes.get(prefix)

    def add(self, route):
        if self.fail:
            raise OSError("Имитируемая ошибка ядра")
        if route.prefix in self.routes:
            raise OSError("Маршрут существует")
        self.routes[route.prefix] = route

    def delete(self, route):
        if self.routes.get(route.prefix) != route:
            raise OSError("Маршрут изменен")
        del self.routes[route.prefix]


class PasswordlessTests(unittest.TestCase):
    def test_policy_only_grants_fixed_commands_without_general_python(self):
        from sshvpn.installation import sudoers, COMMANDS, INSTALL_ROOT
        policy = sudoers('testuser')
        self.assertIn('NOPASSWD: NOSETENV:', policy)
        self.assertNotIn('*', policy)
        self.assertNotIn('python', policy)
        self.assertNotIn('(ALL)', policy)
        for name in COMMANDS:
            self.assertIn(str(INSTALL_ROOT / 'launch') + ' ' + name, policy)
        with self.assertRaises(ValueError):
            sudoers('testuser ALL=(ALL)')

    def test_entry_rejects_arbitrary_commands_before_privileged_work(self):
        from sshvpn.installation import installed_main
        with mock.patch('sshvpn.installation.owner_uid') as owner:
            for arguments in ([], ['connect', '--other'], ['python'], ['check;id']):
                with self.subTest(arguments=arguments), self.assertRaises(RuntimeError):
                    installed_main(arguments)
            owner.assert_not_called()

    def test_secure_paths_reject_nonroot_and_writable_parents(self):
        from sshvpn.installation import secure_path
        from types import SimpleNamespace
        path = Path('/fixed/child')
        with mock.patch.object(Path, 'resolve', return_value=path), \
                mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=501, st_mode=0o755)):
            with self.assertRaisesRegex(RuntimeError, 'Небезопасные права'):
                secure_path(path)
        with mock.patch.object(Path, 'resolve', return_value=path), \
                mock.patch.object(Path, 'stat', side_effect=[SimpleNamespace(st_uid=0, st_mode=0o755),
                    SimpleNamespace(st_uid=0, st_mode=0o775)]):
            with self.assertRaisesRegex(RuntimeError, 'Небезопасные права'):
                secure_path(path)

    def test_source_snapshot_rejects_links_and_ignores_unrelated_files(self):
        from sshvpn.installation import source_files
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for directory in ('vendor', 'sshvpn', 'rules'):
                (root / directory).mkdir()
            for path in ('vpn.py', 'config.json', 'vendor/sing-box', 'vendor/provenance.json',
                         'sshvpn/__init__.py', 'rules/local-domains.txt', 'private.key'):
                (root / path).write_text('test', encoding='utf-8')
            self.assertNotIn(Path('private.key'), source_files(root))
            (root / 'vendor/sing-box').unlink()
            (root / 'vendor/sing-box').symlink_to(root / 'private.key')
            with self.assertRaisesRegex(RuntimeError, 'Недопустимый файл'):
                source_files(root)

    def test_failed_policy_validation_restores_previous_installation(self):
        from sshvpn import installation
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / 'source'
            root.mkdir()
            (root / 'vpn.py').write_text('print(1)', encoding='utf-8')
            helper = Path(name) / 'helpers/master-sshifu'
            helper.mkdir(parents=True)
            (helper / 'previous').write_text('сохранить', encoding='utf-8')
            policy = Path(name) / 'policies/master-sshifu'
            policy.parent.mkdir()
            policy.write_text('previous policy', encoding='utf-8')
            calls = []

            def command(args, **kwargs):
                calls.append(args)
                if args == ['/usr/sbin/visudo', '-c']:
                    raise subprocess.CalledProcessError(1, args)

            with mock.patch.object(installation, 'INSTALL_ROOT', helper), \
                    mock.patch.object(installation, 'POLICY', policy), \
                    mock.patch.object(installation, 'secure_path'), \
                    mock.patch.object(installation, 'owner_uid', return_value=os.getuid()), \
                    mock.patch.object(installation, 'system_python', return_value='/usr/bin/python3'), \
                    mock.patch.object(installation, 'source_files', return_value=[Path('vpn.py')]), \
                    mock.patch('sshvpn.config.load'), mock.patch('sshvpn.runtime.binary'), \
                    mock.patch('sshvpn.installation.subprocess.run', side_effect=command):
                with self.assertRaises(subprocess.CalledProcessError):
                    installation._install_locked(root, os.getuid())
            self.assertEqual((helper / 'previous').read_text(encoding='utf-8'), 'сохранить')
            self.assertEqual(policy.read_text(encoding='utf-8'), 'previous policy')
            self.assertEqual(policy.stat().st_mode & 0o777, 0o440)
            self.assertTrue(any('-cf' in call for call in calls))
            self.assertFalse(any('connect' in call for call in calls))

    def test_isolated_entry_ignores_pythonpath_injection(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name)
            marker = target / 'executed'
            (target / 'sitecustomize.py').write_text(
                'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n', encoding='utf-8')
            env = dict(os.environ, PYTHONPATH=str(target))
            result = subprocess.run([sys.executable, '-I', '-S', '-B', str(ROOT / 'vpn.py'), 'server-config'],
                env=env, cwd=target, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding='utf-8', timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['inbounds'][0]['listen'], '127.0.0.1')
            self.assertFalse(marker.exists())


class InstallerTests(unittest.TestCase):
    def test_bad_archive_hash_never_overwrites_existing_binary(self):
        from tools.install_sing_box import extract_verified
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            archive, target = folder / 'download.tar.gz', folder / 'sing-box'
            archive.write_bytes(b'broken download')
            target.write_bytes(b'existing binary')
            with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                extract_verified(archive, '0' * 64, target)
            self.assertEqual(target.read_bytes(), b'existing binary')

    def test_archive_extracts_only_binary_and_rejects_link(self):
        import io
        import tarfile
        from tools.install_sing_box import extract_verified
        for link in (False, True):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                archive, target = folder / 'download.tar.gz', folder / 'sing-box'
                with tarfile.open(archive, 'w:gz') as bundle:
                    info = tarfile.TarInfo('release/sing-box')
                    if link:
                        info.type, info.linkname = tarfile.SYMTYPE, '/etc/passwd'
                        bundle.addfile(info)
                    else:
                        info.size = 6
                        bundle.addfile(info, io.BytesIO(b'binary'))
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                if link:
                    with self.assertRaises(RuntimeError):
                        extract_verified(archive, digest, target)
                    self.assertFalse(target.exists())
                else:
                    extract_verified(archive, digest, target)
                    self.assertEqual(target.read_bytes(), b'binary')
                    self.assertTrue(os.access(target, os.X_OK))


class DiagnosticsTests(unittest.TestCase):
    def test_collection_is_local_bounded_and_private(self):
        from sshvpn import diagnostics
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / '.runtime').mkdir()
            log = root / '.runtime/events.log'
            log.write_text('x' * 40000 + 'конец', encoding='utf-8')
            self.assertTrue(diagnostics.read_local(log, 32).endswith('конец'))
            self.assertLessEqual(len(diagnostics.read_local(log, 32).encode('utf-8')), 32)
            target = root / 'report.json'
            with mock.patch('sshvpn.diagnostics.read_local', wraps=diagnostics.read_local) as read, \
                    mock.patch('subprocess.check_output') as command, \
                    mock.patch('socket.create_connection') as network:
                result = diagnostics.collect(root, str(target))
            command.assert_not_called()
            network.assert_not_called()
            self.assertFalse(result['network_changed'])
            self.assertFalse(result['internet_requests'])
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertTrue(all('.ssh' not in str(c.args[0]) for c in read.call_args_list))
            self.assertNotIn(str(root / 'config.json'), json.loads(target.read_text(encoding='utf-8'))['files'])

    def test_unreadable_log_preserves_original_failure(self):
        from sshvpn.runtime import log_tail
        from sshvpn.diagnostics import read_local
        with mock.patch.object(Path, 'open', side_effect=PermissionError('Нет доступа')):
            self.assertIn('Нет доступа', log_tail(Path('ssh.log')))
            self.assertIn('error', read_local(Path('ssh.log')))


class RulesTests(unittest.TestCase):
    def test_domain_boundaries_and_idna(self):
        r = Rules.load(ROOT)
        for name in ("RU", "example.ru.", "a.b.example.su", "пример.рф"):
            with self.subTest(name=name):
                self.assertTrue(r.direct(name))
        for name in ("example.ru.evil.com", "example.rus", "suru.com", "github.com"):
            with self.subTest(name=name):
                self.assertFalse(r.direct(name))

    def test_default_exclusions(self):
        r = Rules.load(ROOT)
        self.assertTrue({'ru', 'su', 'xn--p1ai'}.issubset(set(r.domains)))

    def test_private_rules_extend_defaults_without_public_file_changes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'rules').mkdir()
            for filename, value in {'direct-domains.txt': 'ru\n', 'direct-cidrs.txt': '',
                    'local-domains.txt': 'example.com\n', 'local-cidrs.txt': '192.0.2.8/32\n'}.items():
                (root / 'rules' / filename).write_text(value, encoding='utf-8')
            rules = Rules.load(root)
            self.assertTrue(rules.direct('site.ru'))
            self.assertTrue(rules.direct('sub.example.com'))
            self.assertTrue(rules.direct('192.0.2.8'))
            self.assertFalse(rules.direct('example.com.other.net'))
            self.assertEqual((root / 'rules/direct-domains.txt').read_text(encoding='utf-8'), 'ru\n')

    def test_ip_and_cidr(self):
        r = Rules([], ["192.0.2.4", "198.51.100.0/24", "2001:db8::/32"])
        for target in ("192.0.2.4", "198.51.100.12", "2001:db8::1"):
            self.assertTrue(r.direct(target))
        self.assertFalse(r.direct("192.0.2.5"))

    def test_invalid_domains(self):
        for value in ("", "https://example.ru", "x.ru:443", "x..ru", "x_ru", "*.ru", "-x.ru"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain(value)

    def test_strict_ssh_options(self):
        p = {"hostname": ["192.0.2.1"], "port": ["22"], "user": ["tester"],
             "identityfile": ["/tmp/test-key"], "userknownhostsfile": ["/tmp/test-hosts"]}
        args = ssh_command(load(ROOT), "trial", p)
        for option in ("StrictHostKeyChecking=yes", "UpdateHostKeys=no", "BatchMode=yes",
                       "ForwardAgent=no", "ControlPath=none", "ExitOnForwardFailure=yes"):
            self.assertIn(option, args)
        self.assertEqual(args[1:3], ["-F", "/dev/null"])
        self.assertFalse(any(s.startswith("BindInterface=") for s in args))
        self.assertIn("BindInterface=en0", ssh_command(load(ROOT), "full", p))
        self.assertIn("Compression=no", args)
        c = load(ROOT)
        c["ssh_cipher"] = "aes128-gcm@openssh.com"
        self.assertIn("Ciphers=aes128-gcm@openssh.com", ssh_command(c, "trial", p))

    def test_system_start_is_blocked(self):
        result = subprocess.run(["python3", "vpn.py", "start", "--mode", "system"], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)


class ManualTests(unittest.TestCase):
    def test_acceptance_rejects_stale_wrong_server_and_partial_report(self):
        from sshvpn.manual import accepted
        report = {'phase': 'passed', 'finished': 100000,
                  'limited_route_recovery_verified': True,
                  'stages': [{'stage': stage, 'cleanup': {'conflicts': []}}
                             for stage in ('kill', 'hang', 'traffic')]}
        report['stages'][-1]['probe'] = {'ssh_external_ip': '192.0.2.1', 'ru_direct_log_verified': True}
        self.assertTrue(accepted(report, '192.0.2.1', 100001))
        for now, server in ((200000, '192.0.2.1'), (99999, '192.0.2.1'), (100001, '192.0.2.2')):
            with self.subTest(now=now, server=server):
                self.assertFalse(accepted(report, server, now))
        for mutation in ('cleanup', 'probe', 'stages'):
            changed = copy.deepcopy(report)
            if mutation == 'cleanup':
                changed['stages'][0]['cleanup']['conflicts'].append('changed')
            elif mutation == 'probe':
                changed['stages'][-1]['probe']['ru_direct_log_verified'] = False
            else:
                changed['stages'].pop(1)
            self.assertFalse(accepted(changed, '192.0.2.1', 100001))

    def test_manual_without_privilege_or_bounded_duration_does_not_open_files(self):
        from sshvpn.manual import check
        with mock.patch('sshvpn.manual.os.geteuid', return_value=501), \
                mock.patch('sshvpn.manual.os.open') as opened:
            with self.assertRaises(RuntimeError):
                check(ROOT, 300)
            for duration in (0, 179, 601):
                with self.assertRaises(ValueError):
                    check(ROOT, duration)
            opened.assert_not_called()

    def test_manual_mode_cannot_combine_fault_or_unbounded_session(self):
        from sshvpn.system import run
        with mock.patch('sshvpn.system.os.open') as opened:
            for kwargs in ({'duration': 0}, {'fault': 'kill'}, {'self_test': True}, {'protected': True}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    run(ROOT, manual=True, **kwargs)
            opened.assert_not_called()

    def test_manual_requests_use_system_routing_and_verify_real_outputs(self):
        from sshvpn.manual import traffic
        with tempfile.TemporaryDirectory() as folder:
            scratch = Path(folder)
            (scratch / 'engine.log').write_text('outbound/direct[direct]: outbound connection to yandex.ru:443\n', encoding='utf-8')

            def fetch(host, path, folder):
                target = folder / 'body'
                target.write_text('198.51.100.23' if host == 'checkip.amazonaws.com' else '192.0.2.1', encoding='utf-8')
                return {'http_status': 200, 'bytes': 8388608, 'seconds': 2}, target

            with mock.patch('sshvpn.protected.fetch', side_effect=fetch) as request:
                result = traffic({}, scratch, '192.0.2.1', lambda: None, lambda _: None)
            self.assertEqual(result['direct_external_ip'], '198.51.100.23')
            self.assertTrue(result['ru_direct_log_verified'])
            self.assertFalse(result['youtube_playback_verified'])
            self.assertFalse(result['speedtest_completed'])
            self.assertTrue(all(not call.kwargs for call in request.call_args_list))

    def test_manual_probe_stops_on_wrong_external_ip(self):
        from sshvpn.manual import traffic
        with tempfile.TemporaryDirectory() as folder:
            scratch = Path(folder)
            target = scratch / 'body'
            target.write_text('192.0.2.2', encoding='utf-8')
            with mock.patch('sshvpn.protected.fetch', return_value=({'http_status': 200}, target)) as request:
                with self.assertRaisesRegex(RuntimeError, 'не совпал'):
                    traffic({}, scratch, '192.0.2.1', lambda: None, lambda _: None)
                self.assertEqual(request.call_count, 1)


class SessionTests(unittest.TestCase):
    def test_active_vpn_refuses_immediately_without_network_changes(self):
        from sshvpn import system
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            kernel = Kernel()
            kernel.routes['0.0.0.0/1'] = Route('0.0.0.0/1', 'utun4')
            kernel.snapshot = lambda prefixes: {p: kernel.get(p) for p in prefixes}
            before = kernel.routes.copy()
            with mock.patch('sshvpn.system.sys.stdin.isatty', return_value=True), \
                    mock.patch('sshvpn.system.os.geteuid', return_value=0), \
                    mock.patch.dict(os.environ, {'SUDO_UID': str(root.stat().st_uid)}), \
                    mock.patch('sshvpn.system.MacRoutes', return_value=kernel), \
                    mock.patch('sshvpn.system.connected_vpn_clients', return_value=['AmneziaWG']), \
                    mock.patch('sshvpn.system.os.open') as opened, \
                    mock.patch('sshvpn.system.time.sleep') as sleep, \
                    mock.patch('sshvpn.system.command') as execute:
                with self.assertRaises(system.VPNConflictError) as caught:
                    system.run(root, duration=0, interactive=True)
                self.assertEqual(caught.exception.clients, ['AmneziaWG'])
                self.assertEqual(caught.exception.interfaces, ['utun4'])
                opened.assert_not_called()
                sleep.assert_not_called()
                execute.assert_not_called()
            self.assertEqual(kernel.routes, before)

    def test_vpn_names_use_connected_services_or_transport_process(self):
        from sshvpn.system import connected_vpn_clients
        listed = ('* (Disconnected) ID VPN "Happ Plus" [VPN:happ]\n'
                  '* (Connected) ID VPN "Other VPN" [VPN:other]\n')
        with mock.patch('sshvpn.system.command', side_effect=[listed, '/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN\n']):
            self.assertEqual(connected_vpn_clients(), ['Other VPN'])
        with mock.patch('sshvpn.system.command', side_effect=[listed, '/Applications/AmneziaVPN.app/Contents/MacOS/amneziawg-go\n']):
            self.assertEqual(connected_vpn_clients(), ['AmneziaWG', 'Other VPN'])

    def test_console_colors_only_interactive_output(self):
        import io
        from sshvpn.console import show

        class Terminal(io.StringIO):
            def isatty(self):
                return True

        terminal = Terminal()
        with mock.patch.dict(os.environ, {'TERM': 'xterm'}, clear=True):
            show('включено.', 'success', stream=terminal)
            self.assertEqual(terminal.getvalue(), '\033[32mMaster SSHifu: включено.\033[0m\n')
            terminal.seek(0)
            terminal.truncate()
            with mock.patch.dict(os.environ, {'NO_COLOR': '1'}):
                show('включено.', 'success', stream=terminal)
                self.assertEqual(terminal.getvalue(), 'Master SSHifu: включено.\n')
            redirected = io.StringIO()
            show('включено.', 'success', stream=redirected)
            self.assertNotIn('\033', redirected.getvalue())

    def test_interactive_watchdog_finishes_report_only_after_parent_disappears(self):
        from sshvpn.system import watchdog
        for after in (100, 1):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as name:
                read_fd, write_fd = os.pipe()
                os.close(write_fd)
                path = Path(name) / 'routes.json'
                with mock.patch('sshvpn.system.os.getppid', side_effect=[100, after]), \
                        mock.patch('sshvpn.system.rollback', return_value=[]), \
                        mock.patch('sshvpn.system.os.kill') as kill, \
                        mock.patch('sshvpn.session.emergency_report') as finish:
                    watchdog(path, read_fd, 600, interactive=True)
                    kill.assert_not_called()
                    self.assertEqual(finish.call_count, int(after != 100))

    def test_health_fallback_and_wrong_exit(self):
        from sshvpn.session import healthy
        pulse = mock.Mock()
        with mock.patch('sshvpn.system.command', side_effect=[subprocess.TimeoutExpired('curl', 5), '192.0.2.1\n']) as fetch:
            self.assertTrue(healthy('192.0.2.1', pulse))
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(pulse.call_count, 2)
        with mock.patch('sshvpn.system.command', return_value='192.0.2.2\n') as fetch:
            self.assertFalse(healthy('192.0.2.1', lambda: None))
            fetch.assert_called_once()

    def test_full_interactive_flow_starts_without_web_probes_and_rolls_back(self):
        import contextlib
        from sshvpn import system
        for dns_failure in (False, True):
            with self.subTest(dns_failure=dns_failure), tempfile.TemporaryDirectory() as name, contextlib.ExitStack() as stack:
                root = Path(name)
                (root / '.runtime').mkdir()
                scratch = root / 'scratch'
                scratch.mkdir()
                kernel = Kernel()
                baseline = {'0.0.0.0/0': Route('0.0.0.0/0', 'en0', '192.168.3.1')}
                kernel.routes.update(baseline)
                kernel.rows = lambda: []
                kernel.snapshot = lambda prefixes: {p: kernel.get(p) for p in prefixes}
                children, states, readers = [], [], []
                live = {'dns': False, 'tun': False}

                def guarded(*args, **kwargs):
                    child = mock.Mock()
                    child.poll.return_value = None
                    child.process.pid = 12000 + len(children)
                    children.append(child)
                    if len(children) == 2:
                        live['tun'] = True
                    return child

                def popen(args, **kwargs):
                    process = mock.Mock()
                    process.poll.return_value = None
                    process.returncode = 0
                    process.pid = 13000
                    if '_watchdog' in args:
                        self.assertIn('--interactive', args)
                        reader = os.dup(int(args[args.index('_watchdog') + 2]))
                        readers.append(reader)
                    else:
                        live['dns'] = True
                        process.stdin.close.side_effect = lambda: live.update(dns=False)
                    return process

                def command(args, **kwargs):
                    if '_export-system' in args:
                        return json.dumps({'command': ['ssh'], 'server_ip': '192.0.2.1'})
                    if args[0] == '/usr/bin/curl':
                        self.fail('Начальный запуск не должен выполнять веб-запросы')
                    if args[0] == '/usr/sbin/scutil':
                        return '172.31.255.2' if live['dns'] and not dns_failure else 'No such key'
                    return ''

                def changed(state):
                    states.append(copy.deepcopy(state))
                    if state['phase'] == 'ready':
                        (root / '.runtime/system-stop.json').write_text(json.dumps({'run_id': state['run_id']}), encoding='utf-8')

                def cleanup(items):
                    live['tun'] = False
                    for item in items:
                        item.poll.return_value = 0

                config = load(ROOT)
                config['backend_ready'] = True
                replacements = {'STATE': root / 'state.json', 'LOCK': root / 'lock',
                    'command': command, 'MacRoutes': lambda: kernel, 'GuardedProcess': guarded,
                    'binary': lambda _: 'sing-box', 'free_ports': lambda *a, **k: None,
                    'load': lambda _: config, 'client': lambda *a: {'route': {'rules': [{}, {}]}},
                    'terminate': cleanup, 'greeting': lambda _: True}
                for key, value in replacements.items():
                    stack.enter_context(mock.patch.object(system, key, value))
                stack.enter_context(mock.patch('sshvpn.system.Rules.load', return_value=Rules([], [])))
                stack.enter_context(mock.patch('sshvpn.system.os.geteuid', return_value=0))
                stack.enter_context(mock.patch.dict(os.environ, {'SUDO_UID': str(root.stat().st_uid)}))
                stack.enter_context(mock.patch('sshvpn.system.sys.stdin.isatty', return_value=True))
                stack.enter_context(mock.patch('sshvpn.system.signal.signal'))
                stack.enter_context(mock.patch('sshvpn.system.socket.if_nameindex',
                    side_effect=lambda: [(1, 'utun99')] if live['tun'] else [(1, 'en0')]))
                stack.enter_context(mock.patch('sshvpn.system.tempfile.mkdtemp', return_value=str(scratch)))
                stack.enter_context(mock.patch('sshvpn.system.subprocess.Popen', side_effect=popen))
                health = stack.enter_context(mock.patch('sshvpn.session.healthy'))
                traffic = stack.enter_context(mock.patch('sshvpn.manual.traffic'))
                try:
                    if dns_failure:
                        with self.assertRaisesRegex(RuntimeError, 'DNS не зарегистрирован'):
                            system.run(root, duration=0, interactive=True, on_state=changed)
                    else:
                        system.run(root, duration=0, interactive=True, on_state=changed)
                finally:
                    for reader in readers:
                        os.close(reader)
                self.assertEqual(kernel.routes, baseline)
                self.assertFalse(live['tun'])
                self.assertFalse(live['dns'])
                health.assert_not_called()
                traffic.assert_not_called()
                self.assertFalse(any(s['phase'] == 'awaiting_confirmation' for s in states))
                self.assertEqual(any(s.get('persistent') for s in states), not dns_failure)
                self.assertEqual(states[-1]['phase'], 'stopped')
                self.assertEqual(states[-1]['rollback_conflicts'], [])
                if dns_failure:
                    failed = next(s for s in states if s['phase'] == 'failed')
                    self.assertEqual(failed['failure_phase'], 'dns_configuring')
                    self.assertIn('DNS не зарегистрирован', failed['diagnostics']['traceback'])
                    self.assertEqual(states[-1]['failure_phase'], 'dns_configuring')

    def test_interactive_entry_refuses_nonterminal_and_unprivileged_use(self):
        from sshvpn import session
        with mock.patch('sshvpn.session.sys.stdin.isatty', return_value=False), \
                mock.patch('sshvpn.session.os.open') as opened:
            with self.assertRaises(RuntimeError):
                session.connect(ROOT)
            opened.assert_not_called()
        with mock.patch('sshvpn.session.sys.stdin.isatty', return_value=True), \
                mock.patch('sshvpn.session.os.geteuid', return_value=501), \
                mock.patch('sshvpn.session.os.open') as opened:
            with self.assertRaises(RuntimeError):
                session.connect(ROOT)
            opened.assert_not_called()

    def test_interactive_cannot_mix_fault_or_bounded_modes(self):
        from sshvpn.system import run
        with mock.patch('sshvpn.system.os.open') as opened:
            for kwargs in ({'duration': 300}, {'duration': 0, 'manual': True},
                           {'duration': 0, 'self_test': True}, {'duration': 0, 'fault': 'kill'},
                           {'duration': 0, 'protected': True}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    run(ROOT, interactive=True, **kwargs)
            opened.assert_not_called()

    def test_connect_controller_runs_once_without_self_test_or_confirmation(self):
        import contextlib
        import io
        from sshvpn import session
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            final = {'run_id': 'test-session', 'pid': os.getpid(), 'journal': str(root / 'routes.json'),
                     'phase': 'stopped', 'persistent': True}

            def run(*args, **kwargs):
                kwargs['on_state'](dict(final, phase='ready'))
                kwargs['on_state'](dict(final, phase='ready'))
                kwargs['on_state'](final)

            output = io.StringIO()
            with mock.patch.object(session, 'REPORT', root / 'report.json'), \
                    mock.patch.object(session, 'LOG', root / 'events.log'), \
                    mock.patch('sshvpn.session.load', return_value={}), \
                    mock.patch('sshvpn.system.run', side_effect=run) as worker, \
                    mock.patch('sshvpn.system.current', return_value=final), \
                    mock.patch('sshvpn.protected.wait_cleanup'), \
                    mock.patch('sshvpn.protected.cleanup_snapshot', return_value={'verified': True}), \
                    contextlib.redirect_stdout(output):
                report = session._connect_locked(root)
            worker.assert_called_once_with(root, duration=0, interactive=True, on_state=mock.ANY)
            self.assertTrue(report['persistent'])
            self.assertFalse(report['confirmation_required'])
            self.assertFalse(report['startup_web_probes'])
            self.assertNotIn('KEEP', output.getvalue())
            self.assertNotIn('YouTube', output.getvalue())
            self.assertEqual(output.getvalue().splitlines(), [
                'Master SSHifu: подготовка...',
                'Master SSHifu: включено.',
                'Master SSHifu: выключено.'])

    def test_health_failure_records_endpoint_and_exception_without_response_body(self):
        from sshvpn import session
        with mock.patch('sshvpn.session.system.command', side_effect=OSError('Нет сети')), \
                self.assertLogs('sshvpn.session', level='INFO') as logs:
            self.assertFalse(session.healthy('192.0.2.1', lambda: None))
        records = [json.loads(line.split(':', 2)[2]) for line in logs.output]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r['error_type'] == 'OSError' and not r['ok'] for r in records))
        self.assertTrue(all('endpoint' in r and 'seconds' in r for r in records))

    def test_conflicting_vpn_notice_never_claims_enabled(self):
        import contextlib
        import io
        from sshvpn import session, system
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = io.StringIO()
            with mock.patch.object(session, 'REPORT', root / 'report.json'), \
                    mock.patch.object(session, 'LOG', root / 'events.log'), \
                    mock.patch('sshvpn.session.load', return_value={}), \
                    mock.patch('sshvpn.system.run', side_effect=system.VPNConflictError(['utun4'], ['AmneziaWG'])), \
                    mock.patch('sshvpn.system.current', return_value={'pid': 0}), \
                    mock.patch('sshvpn.protected.wait_cleanup') as cleanup, \
                    contextlib.redirect_stdout(output):
                report = session._connect_locked(root)
            self.assertEqual(report['phase'], 'blocked_by_vpn')
            self.assertFalse(report['network_changed'])
            self.assertFalse(report['persistent'])
            self.assertFalse(report['manual_reconnect_required'])
            cleanup.assert_not_called()
            self.assertEqual(output.getvalue().splitlines(), ['Master SSHifu: подготовка...',
                'Master SSHifu: обнаружен другой VPN: AmneziaWG. Не включено.'])

    def test_reconnect_cancellation_closes_previous_child(self):
        from sshvpn.session import reconnect
        previous = mock.Mock()
        previous.poll.return_value = None
        with mock.patch('sshvpn.session.GuardedProcess') as spawn:
            with self.assertRaises(InterruptedError):
                reconnect(previous, [], 'tester', Path('/unused'),
                          {'max_restarts': 2}, lambda: None, lambda: True)
            spawn.assert_not_called()
        previous.terminate.assert_called_once()
        previous.wait.assert_called_once()

    def test_reconnect_exhaustion_releases_failed_child(self):
        from sshvpn.session import reconnect
        previous, failed = mock.Mock(), mock.Mock()
        previous.poll.return_value = 0
        failed.poll.return_value = 7
        with tempfile.TemporaryDirectory() as name, \
                mock.patch('sshvpn.session.GuardedProcess', return_value=failed) as spawn, \
                mock.patch('sshvpn.session.time.monotonic', side_effect=[0, 2, 3, 4]):
            with self.assertRaisesRegex(RuntimeError, 'ограниченное число'):
                reconnect(previous, ['ssh', '-N'], 'tester', Path(name) / 'ssh.log',
                          {'max_restarts': 1, 'connect_timeout': 1}, lambda: None, lambda: False)
            self.assertEqual(spawn.call_count, 1)
        self.assertGreaterEqual(failed.wait.call_count, 1)

    def test_persistent_watchdog_survives_initial_lease_after_readiness(self):
        with tempfile.TemporaryDirectory() as name:
            journal = Path(name) / 'routes.json'
            journal.write_text('[]', encoding='utf-8')
            source = ('import os,subprocess,sys,time\n'
                      'r,w=os.pipe()\n'
                      'p=subprocess.Popen([sys.executable,sys.argv[1],"_watchdog",sys.argv[2],str(r),"1","--interactive"],'
                      'pass_fds=(r,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n'
                      'os.close(r)\nos.write(w,b"R")\n'
                      'for i in range(8):\n os.write(w,b".");time.sleep(.2)\n'
                      'os.close(w)\nsys.exit(p.wait(timeout=3))\n')
            result = subprocess.run([sys.executable, '-c', source, str(ROOT / 'vpn.py'), str(journal)], timeout=6)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads((journal.parent / 'rollback-result.json').read_text(encoding='utf-8')),
                             {'conflicts': []})

    def test_route_monitor_uses_single_consistent_snapshot(self):
        rows = [{'prefix': '0.0.0.0/0', 'interface': 'en0', 'gateway': '192.168.3.1', 'scope': False},
                {'prefix': '0.0.0.0/1', 'interface': 'utun99', 'gateway': 'utun99', 'scope': False}]
        kernel = MacRoutes()
        with mock.patch.object(kernel, 'rows', return_value=rows) as read:
            result = kernel.snapshot(('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1'))
            read.assert_called_once()
        self.assertEqual(result['0.0.0.0/0'], Route('0.0.0.0/0', 'en0', '192.168.3.1'))
        self.assertEqual(result['0.0.0.0/1'], Route('0.0.0.0/1', 'utun99'))
        self.assertIsNone(result['128.0.0.0/1'])


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.kernel, self.saved = Kernel(), []
        self.journal = Journal(self.kernel, lambda entries: self.saved.append(copy.deepcopy(entries)))
        self.route = Route("0.0.0.0/1", "utun99")

    def test_exact_rollback_and_existing_routes(self):
        other = Route("128.0.0.0/1", "utun8")
        self.kernel.add(other)
        self.journal.add(self.route)
        self.assertEqual(self.journal.rollback(), [])
        self.assertEqual(self.kernel.routes, {other.prefix: other})
        self.assertEqual(self.journal.rollback(), [])

    def test_existing_route_never_replaced(self):
        other = Route(self.route.prefix, "utun8")
        self.kernel.add(other)
        with self.assertRaises(RuntimeError):
            self.journal.add(self.route)
        self.assertEqual(self.kernel.get(other.prefix), other)

    def test_changed_route_not_deleted(self):
        self.journal.add(self.route)
        changed = Route(self.route.prefix, "utun8")
        self.kernel.routes[self.route.prefix] = changed
        self.assertEqual(self.journal.rollback(), [self.route.prefix])
        self.assertEqual(self.kernel.get(self.route.prefix), changed)

    def test_partial_failure_rollback(self):
        self.journal.add(self.route)
        self.kernel.fail = True
        with self.assertRaises(OSError):
            self.journal.add(Route("128.0.0.0/1", "utun99"))
        self.assertEqual(self.journal.rollback(), [])
        self.assertEqual(self.kernel.routes, {})

    def test_crash_after_intent_requires_review(self):
        self.journal.entries = [{"route": {"prefix": self.route.prefix, "interface": "utun99", "gateway": ""},
                                 "phase": "intent"}]
        self.kernel.add(self.route)
        self.assertEqual(self.journal.rollback(), [self.route.prefix])
        self.assertEqual(self.kernel.get(self.route.prefix), self.route)


class MeasurementTests(unittest.TestCase):
    def test_truncated_stream_is_rejected(self):
        reader, writer = os.pipe()
        os.write(writer, b"short")
        os.close(writer)
        with os.fdopen(reader, "rb", buffering=0) as stream:
            with self.assertRaises(ConnectionError):
                streamcheck.receive(stream, 20, time.monotonic() + 1)

    def test_partial_http_transfer_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "payload"
            path.write_bytes(b"123")
            data = json.dumps({"code": 200, "downloaded": 3, "uploaded": 0, "seconds": 1, "first_byte": 0.1})
            with mock.patch("sshvpn.benchmark.subprocess.check_output", return_value=data):
                with self.assertRaises(RuntimeError):
                    benchmark.curl(12345, path, download_bytes=20)

    def test_failed_measurement_has_no_successful_median(self):
        error = subprocess.CalledProcessError(22, ["curl"], output='{"code":403}')
        with tempfile.TemporaryDirectory() as name:
            with mock.patch("sshvpn.benchmark.sample", side_effect=error):
                result = benchmark.run(Path(name), ["test-server"], ["default"], 1, 1, 1)
            self.assertFalse(result["all_transfers_complete"])
            self.assertEqual(result["medians"], [])
            data = json.loads(Path(result["report"]).read_text(encoding="utf-8"))
            self.assertEqual(data["samples"][0]["http_code"], 403)


class SystemSafetyTests(unittest.TestCase):
    def test_direct_dns_uses_dhcp_without_public_fallback(self):
        from sshvpn.config import physical_dns
        with mock.patch("sshvpn.config.subprocess.check_output", return_value="192.168.3.1\n") as execute:
            self.assertEqual(physical_dns("en0"), "192.168.3.1")
            self.assertEqual(execute.call_args.args[0],
                             ["/usr/sbin/ipconfig", "getoption", "en0", "domain_name_server"])
        for reply in ("", "invalid", "192.168.3.1 invalid"):
            with self.subTest(reply=reply), mock.patch("sshvpn.config.subprocess.check_output", return_value=reply):
                with self.assertRaises(RuntimeError):
                    physical_dns("en0")

    def test_child_guard_preserves_diagnostic_error(self):
        from sshvpn.runtime import GuardedProcess
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "transport.log"
            with path.open("w", encoding="utf-8") as log:
                child = GuardedProcess([sys.executable, "-c",
                                        "import sys; print('transport refused', file=sys.stderr); sys.exit(7)"], stderr=log)
                self.assertEqual(child.wait(timeout=5), 7)
            self.assertEqual(path.read_text(encoding="utf-8").strip(), "transport refused")

    def test_disabled_adapter_never_restarts_amnezia(self):
        with mock.patch.object(recovery, "require_acceptance"), \
                mock.patch.object(recovery, "ensure_profile"), \
                mock.patch.object(recovery, "stop_test"), \
                mock.patch.object(recovery, "connected_amnezia", return_value=False), \
                mock.patch.object(recovery, "call") as execute:
            event = mock.Mock()
            self.assertFalse(recovery.restore(ROOT, {"expected_ip": "192.0.2.1"}, event))
            execute.assert_not_called()
            self.assertEqual(event.call_args.args[0], "failed")

    def test_limited_routes_reject_global_and_foreign_targets(self):
        kernel = Kernel()
        kernel.routes["0.0.0.0/0"] = Route("0.0.0.0/0", "en0", "192.168.3.1")
        limited = protected.LimitedRoutes(kernel, "en0", "192.0.2.30")
        original = kernel.routes.copy()
        for route in (Route("0.0.0.0/0", "utun99"), Route("0.0.0.0/1", "utun99"),
                      Route("128.0.0.0/1", "utun99"), Route("::/1", "utun99"),
                      Route("198.18.0.0/15", "utun99"), Route("1.1.1.1/32", "utun99"),
                      Route("198.18.0.1/32", "utun4"), Route("198.18.0.1/32", "utun99", "1.1.1.1"),
                      Route("0.0.0.0/0%en0", "en0", "192.168.3.254")):
            with self.subTest(route=route), self.assertRaises(RuntimeError):
                limited.add(route)
        self.assertEqual(kernel.routes, original)

    def test_limited_routes_rollback_preserves_existing_vpn(self):
        kernel = Kernel()
        kernel.routes = {"0.0.0.0/0": Route("0.0.0.0/0", "en0", "192.168.3.1"),
                         "0.0.0.0/1": Route("0.0.0.0/1", "utun4"),
                         "128.0.0.0/1": Route("128.0.0.0/1", "utun4")}
        original = kernel.routes.copy()
        journal = Journal(protected.LimitedRoutes(kernel, "en0", "192.0.2.30"), lambda _: None)
        for route in (Route("0.0.0.0/0%en0", "en0", "192.168.3.1"),
                      Route("192.0.2.30/32", "en0", "192.168.3.1"),
                      Route("198.18.0.1/32", "utun99"), Route("192.0.2.123/32", "utun99"),
                      Route("2001:db8:ffff::123/128", "utun99")):
            journal.add(route)
        self.assertEqual(journal.rollback(), [])
        self.assertEqual(kernel.routes, original)

    def test_protected_baseline_requires_existing_vpn(self):
        kernel = Kernel()
        for interfaces in ((None, None), ("utun4", None), ("utun4", "utun5"),
                           ("en0", "en0"), ("utun99", "utun99")):
            kernel.routes = {p: Route(p, i) for p, i in zip(("0.0.0.0/1", "128.0.0.0/1"), interfaces) if i}
            with self.subTest(interfaces=interfaces), self.assertRaises(RuntimeError):
                protected.baseline_routes(kernel)
        kernel.routes = {p: Route(p, "utun4") for p in ("0.0.0.0/1", "128.0.0.0/1")}
        self.assertEqual(protected.baseline_routes(kernel)["0.0.0.0/1"]["interface"], "utun4")

    def test_probe_rejects_real_or_multiple_dns_addresses(self):
        for text in ("1.1.1.1\n", "198.18.0.1\n198.18.0.2\n", "", "::1\n"):
            with self.subTest(text=text), mock.patch("sshvpn.system.command", return_value=text):
                with self.assertRaises(RuntimeError):
                    protected.fake_address("example.com", 43153)
        with mock.patch("sshvpn.system.command", return_value="198.18.0.1\n"):
            self.assertEqual(protected.fake_address("example.com", 43153), "198.18.0.1")

    def test_probe_curl_does_not_follow_outside_test_routes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "example.com.body").write_bytes(b"abc")
            with mock.patch("sshvpn.system.command", return_value="302 3 0.5") as execute:
                value, _ = protected.fetch("example.com", "/", root, address="198.18.0.1")
            self.assertEqual(value["http_status"], 302)
            args = execute.call_args.args[0]
            self.assertNotIn("-L", args)
            self.assertNotIn("--location", args)
            self.assertIn("example.com:443:198.18.0.1", args)
            self.assertNotIn("--insecure", args)

    def test_cleanup_rejects_residual_route_even_after_success_marker(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            route = Route("198.18.0.1/32", "utun99")
            (root / "rollback-result.json").write_text('{"conflicts": []}', encoding="utf-8")
            journal = root / "routes.json"
            journal.write_text(json.dumps([{"phase": "removed", "route": {
                "prefix": route.prefix, "interface": route.interface, "gateway": ""}}]), encoding="utf-8")
            with mock.patch("sshvpn.protected.socket.if_nameindex", return_value=[]), \
                    mock.patch("sshvpn.system.MacRoutes.get", return_value=route):
                with self.assertRaises(RuntimeError):
                    protected.wait_cleanup({"journal": str(journal)}, timeout=0.05)

    def test_cleanup_accepts_closed_tcp_with_time_wait(self):
        from sshvpn.runtime import free_ports
        listeners = [socket.socket() for _ in range(3)]
        try:
            for listener in listeners:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
            c = dict(zip(('listen_port', 'forward_port', 'dns_port'),
                         [listener.getsockname()[1] for listener in listeners]))
            for listener in listeners:
                with socket.create_connection(listener.getsockname()) as peer:
                    accepted, _ = listener.accept()
                    accepted.close()
                    self.assertEqual(peer.recv(1), b'')
                listener.close()
            free_ports(c, reuse_tcp=True)
        finally:
            for listener in listeners:
                listener.close()

    def test_cleanup_rejects_live_tcp_and_udp_owners(self):
        from sshvpn.runtime import free_ports
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with self.subTest(kind=kind), socket.socket(socket.AF_INET, kind) as owner:
                owner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                owner.bind(('127.0.0.1', 0))
                if kind == socket.SOCK_STREAM:
                    owner.listen(1)
                port = owner.getsockname()[1]
                with self.assertRaises(OSError):
                    free_ports({'listen_port': port, 'forward_port': port, 'dns_port': port}, reuse_tcp=True)

    def test_cleanup_accepts_new_vpn_after_recorded_removal(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            (folder / 'cleanup-result.json').write_text('{"conflicts": [], "watchdog_returncode": 1}', encoding='utf-8')
            path = folder / 'routes.json'
            path.write_text(json.dumps([{'phase': 'removed', 'route': {
                'prefix': '0.0.0.0/1', 'interface': 'utun99', 'gateway': ''}}]), encoding='utf-8')
            with mock.patch('sshvpn.protected.socket.if_nameindex', return_value=[]), \
                    mock.patch('sshvpn.system.MacRoutes.get', return_value=Route('0.0.0.0/1', 'utun4')):
                self.assertTrue(protected.cleanup_snapshot({'journal': str(path)})['verified'])

    def test_cleanup_timeout_names_missing_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'routes.json'
            path.write_text('[]', encoding='utf-8')
            with mock.patch('sshvpn.protected.socket.if_nameindex', return_value=[]):
                with self.assertRaisesRegex(RuntimeError, 'Нет итогового файла отката'):
                    protected.wait_cleanup({'journal': str(path)}, timeout=0.05)

    def test_cleanup_does_not_reclaim_reappeared_physical_route(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            (folder / 'rollback-result.json').write_text('{"conflicts": []}', encoding='utf-8')
            path = folder / 'routes.json'
            entry = {'phase': 'removed', 'route': {'prefix': '192.0.2.1/32',
                     'interface': 'en0', 'gateway': '192.168.3.1'}}
            path.write_text(json.dumps([entry]), encoding='utf-8')
            with mock.patch('sshvpn.protected.socket.if_nameindex', return_value=[]), \
                    mock.patch('sshvpn.system.MacRoutes.get', return_value=Route(**entry['route'])), \
                    mock.patch('sshvpn.system.MacRoutes.delete') as delete:
                result = protected.cleanup_snapshot({'journal': str(path)})
                self.assertTrue(result['verified'])
                self.assertTrue(result['routes'][0]['physical_route_present_after_removal'])
                entry['phase'] = 'owned'
                path.write_text(json.dumps([entry]), encoding='utf-8')
                self.assertFalse(protected.cleanup_snapshot({'journal': str(path)})['verified'])
                delete.assert_not_called()

    def test_fault_injection_rejected_for_live_system(self):
        from sshvpn.system import run
        with mock.patch("sshvpn.system.os.open") as opened:
            with self.assertRaises(ValueError):
                run(ROOT, fault="kill")
            opened.assert_not_called()

    def test_unprivileged_protected_check_cannot_change_network(self):
        with mock.patch("sshvpn.protected.os.geteuid", return_value=501), \
                mock.patch("sshvpn.protected.os.open") as opened:
            with self.assertRaises(RuntimeError):
                protected.check(ROOT, "192.0.2.20")
            opened.assert_not_called()

    def test_unaccepted_recovery_refuses_before_any_mutation(self):
        with mock.patch("sshvpn.recovery.stop_test") as stop_test, \
                mock.patch("sshvpn.recovery.call") as execute:
            with self.assertRaises(RuntimeError):
                recovery.restore(ROOT, {}, lambda *a, **k: None)
            stop_test.assert_not_called()
            execute.assert_not_called()

    def test_unaccepted_timer_cannot_register_job(self):
        with mock.patch("sshvpn.recovery.call") as call, \
                mock.patch("sshvpn.recovery.preferences") as read:
            with self.assertRaises(RuntimeError):
                recovery.arm(ROOT, 60, "192.0.2.1")
            call.assert_not_called()
            read.assert_not_called()

    def test_legacy_index_is_not_used_for_connection(self):
        import plistlib
        data = {"Servers.defaultServerIndex": 0, "Servers.defaultServerId": "selected-fourth",
                "Servers.serversList": b"encrypted", "Conf.autoConnect": False,
                "Conf.routeMode": 2, "Conf.sitesSplitTunnelingEnabled": True,
                "Conf.appsRouteMode": 2, "Conf.killSwitchEnabled": False, "Conf.ExceptSites": {}}
        with mock.patch.object(Path, "read_bytes", return_value=plistlib.dumps(data)):
            snapshot = recovery.preferences()
        self.assertNotIn("server_index", snapshot)
        with mock.patch("sshvpn.recovery.preferences", return_value=snapshot):
            with self.assertRaises(RuntimeError):
                recovery.ensure_profile(snapshot)

    def test_profile_is_checked_before_stopping_existing_connection(self):
        with mock.patch("sshvpn.recovery.require_acceptance"), \
                mock.patch("sshvpn.recovery.ensure_profile", side_effect=RuntimeError("Несовпадение")), \
                mock.patch("sshvpn.recovery.stop_test") as stop_test:
            with self.assertRaises(RuntimeError):
                recovery.restore(ROOT, {}, lambda *a, **k: None)
            stop_test.assert_not_called()

    def test_watchdog_survives_parent_exit(self):
        with tempfile.TemporaryDirectory() as name:
            journal = Path(name) / "routes.json"
            journal.write_text("[]", encoding="utf-8")
            source = ("import os,subprocess,sys\n"
                      "r,w=os.pipe()\n"
                      "p=subprocess.Popen([sys.executable,sys.argv[1],'_watchdog',sys.argv[2],str(r),'20'],"
                      "pass_fds=(r,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n"
                      "os.close(r)\n"
                      "os._exit(0)\n")
            subprocess.run([sys.executable, "-c", source, str(ROOT / "vpn.py"), str(journal)], check=True)
            deadline = time.monotonic() + 5
            result = journal.parent / "rollback-result.json"
            while not result.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(json.loads(result.read_text(encoding="utf-8")), {"conflicts": []})

    def test_watchdog_lease_stops_hung_parent(self):
        with tempfile.TemporaryDirectory() as name:
            journal = Path(name) / "routes.json"
            journal.write_text("[]", encoding="utf-8")
            source = ("import os,subprocess,sys,time\n"
                      "r,w=os.pipe()\n"
                      "p=subprocess.Popen([sys.executable,sys.argv[1],'_watchdog',sys.argv[2],str(r),'1'],"
                      "pass_fds=(r,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n"
                      "os.close(r)\ntime.sleep(20)\n")
            p = subprocess.Popen([sys.executable, "-c", source, str(ROOT / "vpn.py"), str(journal)])
            try:
                self.assertEqual(p.wait(timeout=6), -9)
                deadline = time.monotonic() + 3
                result = journal.parent / "rollback-result.json"
                while not result.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(json.loads(result.read_text(encoding="utf-8")), {"conflicts": []})
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()

    def test_real_route_formats_and_scopes(self):
        text = ("0/1 utun8 UScg utun8\n"
                "default 192.168.3.1 UGScg en0\n"
                "default 192.168.3.1 UGScIg en0\n"
                "192.168.3 link#11 UCS en0 !\n")
        rows = parse_routes(text, "inet")
        self.assertEqual([r["prefix"] for r in rows],
                         ["0.0.0.0/1", "0.0.0.0/0", "0.0.0.0/0", "192.168.3.0/24"])
        self.assertEqual([r["scope"] for r in rows], [False, False, True, False])
        kernel = MacRoutes()
        with mock.patch.object(kernel, "rows", return_value=rows):
            self.assertEqual(kernel.get("0.0.0.0/0%en0"), Route("0.0.0.0/0%en0", "en0", "192.168.3.1"))
            self.assertEqual(kernel.get("0.0.0.0/1"), Route("0.0.0.0/1", "utun8"))
            self.assertIsNone(kernel.get("128.0.0.0/1"))
        self.assertEqual(canonical("8000::/1", "inet6"), "8000::/1")
        self.assertEqual(canonical("2001:db8::123", "inet6"), "2001:db8::123/128")

    def test_route_deletion_rechecks_owner(self):
        kernel = MacRoutes()
        with mock.patch.object(kernel, "get", return_value=Route("0.0.0.0/1", "utun8")), \
                mock.patch.object(kernel, "change") as change:
            with self.assertRaises(RuntimeError):
                kernel.delete(Route("0.0.0.0/1", "utun99"))
            change.assert_not_called()

    def test_scoped_route_never_changes_global_default(self):
        kernel = MacRoutes()
        with mock.patch("sshvpn.system.command") as execute:
            kernel.add(Route("0.0.0.0/0%en0", "en0", "192.168.3.1"))
        args = execute.call_args.args[0]
        self.assertEqual(args, ["/sbin/route", "-n", "add", "-inet", "-net", "0.0.0.0/0",
                                "-ifscope", "en0", "192.168.3.1"])

    def test_dns_uses_temporary_key_and_rejects_injection(self):
        script = dns_script("State:/Network/Service/SSH-Split-test/DNS")
        self.assertIn('SupplementalMatchDomains * ""', script)
        self.assertIn("/DNS temporary\n", script)
        self.assertNotIn("set ", script)
        for key in ("Setup:/Network/Global/DNS", "State:/Network/Service/SSH-Split-test\nremove other"):
            with self.assertRaises(ValueError):
                dns_script(key)

    def test_system_fakeip_preserves_domains_without_auto_route(self):
        generated = client(load(ROOT), Rules.load(ROOT), "system")
        tun = next(i for i in generated["inbounds"] if i["type"] == "tun")
        self.assertFalse(tun["auto_route"])
        self.assertEqual(tun["dns_mode"], "disabled")
        self.assertEqual(generated["dns"]["rules"][0]["server"], "dns-fake")
        self.assertEqual(generated["route"]["final"], "ssh")
        self.assertFalse(any(r.get("ip_is_private") for r in generated["route"]["rules"]))


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ssh-split-lab-")
        cls.root = Path(cls.temp.name)
        cls.children = []
        cls.direct_dns = DNS("127.0.0.1")
        cls.remote_dns = DNS("127.0.0.1")
        cls.c = load(ROOT)
        for key in ("listen_port", "forward_port", "dns_port", "remote_socks_port"):
            cls.c[key] = port()
        cls.ssh_port = port()
        cls.c["dns_direct"] = cls.c["dns_tunnel"] = "127.0.0.1"
        cls.executable = binary(ROOT)
        for name in ("host", "client", "wrong"):
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.root / name)], check=True)
        host = (cls.root / "host.pub").read_text(encoding="utf-8").split()
        (cls.root / "known_hosts").write_text(f"[127.0.0.1]:{cls.ssh_port} {host[0]} {host[1]}\n", encoding="utf-8")
        sshd = (f"ListenAddress 127.0.0.1\nPort {cls.ssh_port}\nHostKey {cls.root / 'host'}\n"
                f"PidFile {cls.root / 'sshd.pid'}\nAuthorizedKeysFile {cls.root / 'client.pub'}\n"
                "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
                "AllowTcpForwarding local\nGatewayPorts no\nPermitTunnel no\nX11Forwarding no\n"
                "AllowAgentForwarding no\nLogLevel ERROR\n")
        (cls.root / "sshd_config").write_text(sshd, encoding="utf-8")
        cls.spawn(["/usr/sbin/sshd", "-D", "-e", "-f", str(cls.root / "sshd_config")])
        cls.wait_port(cls.ssh_port)
        backend = server(cls.c["remote_socks_port"])
        backend["dns"] = {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {
            "via.ssh.test": ["127.0.0.1"], "via.direct.test": ["127.0.0.1"],
            "notdirect.test": ["127.0.0.1"], "direct.test.evil.test": ["127.0.0.1"]}}]}
        backend["route"]["default_domain_resolver"] = "hosts"
        backend["route"]["rules"] = [{"domain_suffix": ["direct.test"], "action": "reject"}]
        write(cls.root / "server.json", backend)
        cls.spawn([cls.executable, "run", "-c", str(cls.root / "server.json")])
        cls.wait_port(cls.c["remote_socks_port"])
        cls.command = ["/usr/bin/ssh", "-F", "/dev/null", "-N", "-T", "-n", "-p", str(cls.ssh_port),
                       "-i", str(cls.root / "client"), "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                       "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "IdentitiesOnly=yes",
                       "-o", "ExitOnForwardFailure=yes", "-o", f"UserKnownHostsFile={cls.root / 'known_hosts'}",
                       "-L", f"127.0.0.1:{cls.c['forward_port']}:127.0.0.1:{cls.c['remote_socks_port']}",
                       getpass.getuser() + "@127.0.0.1"]
        cls.forward = cls.spawn(cls.command)
        cls.wait_port(cls.c["forward_port"])
        rules = Rules(["direct.test"], [])
        generated = client(cls.c, rules, "full", interface="lo0", dns_ports={
            "dns-direct": cls.direct_dns.port, "dns-ssh": cls.remote_dns.port})
        write(cls.root / "client.json", generated)
        cls.spawn([cls.executable, "run", "-c", str(cls.root / "client.json")])
        cls.wait_port(cls.c["listen_port"])

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    while data := self.request.recv(65536):
                        self.request.sendall(data)
                except OSError:
                    pass

        class Datagram(socketserver.BaseRequestHandler):
            def handle(self):
                data, stream = self.request
                stream.sendto(data, self.client_address)

        cls.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        cls.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Datagram)
        for item in (cls.tcp, cls.udp):
            item.daemon_threads = True
            threading.Thread(target=item.serve_forever, daemon=True).start()

    @classmethod
    def spawn(cls, command):
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.children.append(process)
        return process

    @classmethod
    def wait_port(cls, number):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", number), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Тестовый порт не открылся")

    @classmethod
    def tearDownClass(cls):
        for process in reversed(cls.children):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for item in (cls.tcp, cls.udp):
            item.shutdown()
            item.server_close()
        cls.direct_dns.close()
        cls.remote_dns.close()
        cls.temp.cleanup()

    def echo(self, target, count=524288):
        stream, _ = socks(self.c["listen_port"], target, self.tcp.server_address[1])
        payload = bytes(range(256)) * (count // 256)
        with stream:
            stream.sendall(payload)
            received = receive(stream, len(payload))
        self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(payload).digest())
        self.assertEqual(len(received), count)

    def test_tcp_direct_bypasses_rejecting_backend(self):
        with self.assertRaises(ConnectionError):
            socks(self.c["forward_port"], "via.direct.test", self.tcp.server_address[1])
        self.echo("via.direct.test")

    def test_fakeip_domains_route_in_real_engine(self):
        c = self.c.copy()
        c["listen_port"], c["dns_port"] = port(), port()
        generated = client(c, Rules(["direct.test"], []), "system", interface="lo0", dns_ports={
            "dns-direct": self.direct_dns.port, "dns-ssh": self.remote_dns.port})
        generated["inbounds"] = [i for i in generated["inbounds"] if i["type"] != "tun"]
        path = self.root / "fakeip.json"
        write(path, generated)
        process = self.spawn([self.executable, "run", "-c", str(path)])
        try:
            self.wait_port(c["listen_port"])
            for name in ("via.direct.test", "via.ssh.test"):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                    stream.settimeout(3)
                    stream.sendto(query(name), ("127.0.0.1", c["dns_port"]))
                    answer = stream.recv(4096)
                address = socket.inet_ntoa(answer[-4:])
                self.assertTrue(address.startswith("198.18.") or address.startswith("198.19."))
                stream, _ = socks(c["listen_port"], address, self.tcp.server_address[1])
                with stream:
                    stream.sendall(b"fakeip-path-check")
                    self.assertEqual(receive(stream, 17), b"fakeip-path-check")
        finally:
            process.terminate()
            process.wait(timeout=3)

    def test_tcp_through_ssh_complete_payload(self):
        self.echo("via.ssh.test")

    def test_stream_measurement_verifies_both_directions(self):
        base = self.command.copy()
        index = base.index("-L")
        del base[index:index + 2]
        command = streamcheck.command(base, 524288, 262144)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, bufsize=0)
        try:
            result = streamcheck.transfer(process, 524288, 262144)
            for direction in ("download", "upload"):
                self.assertTrue(result[direction]["sha256_verified"])
                self.assertGreater(result[direction]["mbit_per_second"], 0)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)
            process.stdin.close()
            process.stdout.close()

    def test_domain_boundaries_in_real_engine(self):
        for name in ("notdirect.test", "direct.test.evil.test"):
            before = len(self.direct_dns.names)
            self.echo(name, count=4096)
            self.assertEqual(len(self.direct_dns.names), before)

    def test_udp_roundtrip_over_ssh(self):
        control, bound = socks(self.c["listen_port"], "127.0.0.1", 0, command=3)
        payload = b"udp-through-ssh" * 80
        header = b"\0\0\0\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", self.udp.server_address[1])
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.sendto(header + payload, ("127.0.0.1", bound[1]))
            response = stream.recv(65535)
        self.assertEqual(udp_payload(response), payload)

    def test_udp_direct_bypasses_ssh(self):
        control, bound = socks(self.c["listen_port"], "127.0.0.1", 0, command=3)
        target = b"via.direct.test"
        payload = b"direct-datagram" * 40
        header = b"\0\0\0\x03" + bytes([len(target)]) + target + struct.pack("!H", self.udp.server_address[1])
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.sendto(header + payload, ("127.0.0.1", bound[1]))
            response = stream.recv(65535)
        self.assertEqual(udp_payload(response), payload)

    def test_split_dns_udp_and_tcp(self):
        for name, destination, other in (("dns.direct.test", self.direct_dns, self.remote_dns),
                                         ("dns.ssh.test", self.remote_dns, self.direct_dns)):
            for kind in ("udp", "tcp"):
                with self.subTest(name=name, kind=kind):
                    packet = query(name, 400 + len(destination.names))
                    before = len(other.names)
                    if kind == "udp":
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                            stream.settimeout(3)
                            stream.sendto(packet, ("127.0.0.1", self.c["dns_port"]))
                            response = stream.recv(4096)
                    else:
                        with socket.create_connection(("127.0.0.1", self.c["dns_port"]), timeout=3) as stream:
                            stream.sendall(struct.pack("!H", len(packet)) + packet)
                            response = receive(stream, struct.unpack("!H", receive(stream, 2))[0])
                    self.assertEqual(response[:2], packet[:2])
                    self.assertEqual(response[-4:], socket.inet_aton("127.0.0.1"))
                    self.assertIn(name, destination.names)
                    self.assertEqual(len(other.names), before)

    def test_wrong_host_key_rejected(self):
        wrong = (self.root / "wrong.pub").read_text(encoding="utf-8").split()
        path = self.root / "wrong_hosts"
        path.write_text(f"[127.0.0.1]:{self.ssh_port} {wrong[0]} {wrong[1]}\n", encoding="utf-8")
        command = self.command.copy()
        command[command.index(f"UserKnownHostsFile={self.root / 'known_hosts'}")] = f"UserKnownHostsFile={path}"
        index = command.index("-L")
        del command[index:index + 2]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Host key verification failed", result.stderr)

    def test_supervisor_stop_crash_and_bounded_reconnect(self):
        with tempfile.TemporaryDirectory(prefix="supervisor-") as name:
            root = Path(name)
            shutil.copytree(ROOT / "rules", root / "rules")
            (root / "vendor").mkdir()
            (root / "vendor/sing-box").symlink_to(ROOT / "vendor/sing-box")
            shutil.copy(ROOT / "vendor/provenance.json", root / "vendor/provenance.json")
            c = load(ROOT)
            for key in ("listen_port", "forward_port", "dns_port", "remote_socks_port"):
                c[key] = port()
            c["max_restarts"] = 1
            write(root / "config.json", c)
            command = self.command.copy()
            command[command.index("-L")] = "-D"
            command[command.index("-D") + 1] = f"127.0.0.1:{c['forward_port']}"
            ctx = multiprocessing.get_context("spawn")
            process = ctx.Process(target=supervise, args=(root, "trial", "stop-test", command))
            process.start()
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and status(root)["phase"] != "ready":
                    time.sleep(0.1)
                self.assertEqual(status(root)["phase"], "ready")
                result = stop(root)
                self.assertFalse(result["running"])
                self.assertEqual(result["phase"], "stopped")
                self.assertFalse(greeting(c["listen_port"]))
                self.assertFalse(greeting(c["forward_port"]))
            finally:
                process.join(timeout=5)
                if process.is_alive():
                    process.terminate()
                    process.join()
            process = ctx.Process(target=supervise, args=(root, "trial", "crash-test", command))
            process.start()
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and status(root)["phase"] != "ready":
                    time.sleep(0.1)
                self.assertEqual(status(root)["phase"], "ready")
                process.kill()
                process.join(timeout=5)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and (greeting(c["listen_port"]) or greeting(c["forward_port"])):
                    time.sleep(0.1)
                self.assertFalse(greeting(c["listen_port"]))
                self.assertFalse(greeting(c["forward_port"]))
                self.assertEqual(status(root)["phase"], "interrupted")
            finally:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=5)
            process = ctx.Process(target=supervise, args=(root, "trial", "failure-test", ["/usr/bin/false"]))
            process.start()
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail("Переподключение не ограничено")
            value = status(root)
            self.assertEqual(value["phase"], "failed")
            self.assertEqual(value["restarts"], 1)
            self.assertFalse(value["running"])
            self.assertLess((root / ".runtime/events.log").stat().st_size, 131072)

    def test_known_domain_has_no_sniff_delay(self):
        class Banner(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"ready\n")

        listener = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
        listener.daemon_threads = True
        threading.Thread(target=listener.serve_forever, daemon=True).start()
        c = self.c.copy()
        c["listen_port"], c["dns_port"] = port(), port()
        legacy = client(c, Rules(["direct.test"], []), "full", interface="lo0", dns_ports={
            "dns-direct": self.direct_dns.port, "dns-ssh": self.remote_dns.port})
        for i, rule in enumerate(legacy["route"]["rules"]):
            if rule.get("action") == "sniff":
                legacy["route"]["rules"][i] = {"action": "sniff", "sniffer": ["http", "tls"], "timeout": "300ms"}
        write(self.root / "legacy.json", legacy)
        process = self.spawn([self.executable, "run", "-c", str(self.root / "legacy.json")])
        self.wait_port(c["listen_port"])
        durations = {"legacy": [], "current": []}
        try:
            for _ in range(3):
                for name, local_port in (("legacy", c["listen_port"]), ("current", self.c["listen_port"])):
                    started = time.monotonic()
                    stream, _ = socks(local_port, "via.ssh.test", listener.server_address[1])
                    with stream:
                        self.assertEqual(receive(stream, 6), b"ready\n")
                    durations[name].append(time.monotonic() - started)
            before = statistics.median(durations["legacy"])
            after = statistics.median(durations["current"])
            print(f"\n  Задержка приветствия: было {before * 1000:.1f} мс, стало {after * 1000:.1f} мс", flush=True)
            self.assertGreater(before - after, 0.20)
        finally:
            process.terminate()
            process.wait(timeout=3)
            listener.shutdown()
            listener.server_close()

    def test_z_ssh_failure_does_not_fallback_to_direct(self):
        self.forward.terminate()
        self.forward.wait(timeout=3)
        stream = None
        try:
            stream, _ = socks(self.c["listen_port"], "via.ssh.test", self.tcp.server_address[1])
            stream.sendall(b"must-fail")
            self.assertEqual(stream.recv(100), b"")
        except (OSError, ConnectionError):
            pass
        finally:
            if stream is not None:
                stream.close()
        self.echo("via.direct.test", count=4096)
        control, bound = socks(self.c["listen_port"], "127.0.0.1", 0, command=3)
        header = b"\0\0\0\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", self.udp.server_address[1])
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(1)
            stream.sendto(header + b"must-not-leak", ("127.0.0.1", bound[1]))
            with self.assertRaises(socket.timeout):
                stream.recv(1024)
        before = len(self.direct_dns.names)
        packet = query("failure.ssh.test", 5555)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(1)
            stream.sendto(packet, ("127.0.0.1", self.c["dns_port"]))
            try:
                response = stream.recv(4096)
                self.assertNotEqual(response[3] & 15, 0)
            except socket.timeout:
                pass
        self.assertEqual(len(self.direct_dns.names), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
