"""Команды проекта и безопасная диагностика."""

import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from . import PROJECT_NAME
from .config import client, load, server, write
from .rules import Rules
from .runtime import binary, directory, start, status, stop, supervise
from .transport import profile, ssh_command

ROOT = Path(__file__).resolve().parent.parent


def external(root, c):
    state = status(root)
    if not state["running"] or state["phase"] != "ready":
        raise RuntimeError("Сначала запустите пробный режим")
    base = ["/usr/bin/curl", "--noproxy", "", "--fail", "--silent", "--show-error",
            "--connect-timeout", "10", "--max-time", "40", "--socks5-hostname", f"127.0.0.1:{c['listen_port']}"]
    ip = subprocess.check_output(base + ["https://api.ipify.org"], encoding="utf-8").strip()
    ipaddress.ip_address(ip)
    expected = profile(c["ssh_alias"])["hostname"][0]
    if ip != expected:
        raise RuntimeError("Внешний адрес SSH не совпал с выбранным сервером")
    with tempfile.TemporaryDirectory(prefix="probe-", dir=directory(root)) as name:
        target = Path(name) / "payload"
        metrics = subprocess.check_output(base + ["-o", str(target), "-w", "%{size_download} %{time_total}",
                                         "https://speed.cloudflare.com/__down?bytes=1048576"], encoding="utf-8")
        if target.stat().st_size != 1048576 or int(metrics.split()[0]) != 1048576:
            raise RuntimeError("Передача не завершена")
    seconds = float(metrics.split()[1])
    return {"ssh_external_ip": ip, "completed_bytes": 1048576, "seconds": seconds,
            "mbit_per_second": round(8.388608 / seconds, 2), "system_vpn_verified": False}


def plan(root, c, rules):
    run = directory(root)
    target = run / "system-plan.json"
    write(target, client(c, rules, "system"))
    routes = subprocess.check_output(["/usr/sbin/netstat", "-rn", "-f", "inet"], encoding="utf-8")
    conflicts = [line.strip() for line in routes.splitlines() if line.split() and line.split()[0] in ("0/1", "128.0/1")]
    return {"activation": "blocked_pending_recovery_acceptance", "config": str(target),
            "tun": "utun99", "auto_route": False, "dns_mode": "disabled",
            "proposed_prefixes": ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"],
            "existing_ipv4_conflicts": conflicts,
            "backend_ready": c["backend_ready"],
            "next_safe_step": "protected-check --expected-ip CURRENT_VPN_IP",
            "required_acceptance": ["ограниченная проверка TUN и аварийного отката при включенной Amnezia",
                                    "независимый рабочий резерв до отключения исходного VPN",
                                    "YouTube, Speedtest и прямой выход ru",
                                    "реальный аварийный откат с системными маршрутами"]}


def main():
    parser = argparse.ArgumentParser(description=PROJECT_NAME + " - SSH VPN для Mac")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("start")
    p.add_argument("--mode", choices=["trial", "full", "system"], default="trial")
    p.add_argument("--duration", type=int, default=600)
    sub.add_parser("stop")
    sub.add_parser("status")
    p = sub.add_parser("check")
    p.add_argument("--local", action="store_true")
    p.add_argument("--external", action="store_true")
    sub.add_parser("plan")
    p = sub.add_parser("match")
    p.add_argument("target")
    sub.add_parser("server-config")
    sub.add_parser("system-self-test")
    sub.add_parser("cleanup-audit")
    sub.add_parser("connect")
    p = sub.add_parser('diagnose')
    p.add_argument('--output')
    p = sub.add_parser("protected-check")
    p.add_argument("--expected-ip", required=True)
    p = sub.add_parser("manual-check")
    p.add_argument("--duration", type=int, default=300)
    p = sub.add_parser("_manual-worker", help=argparse.SUPPRESS)
    p.add_argument("--duration", type=int, required=True)
    p = sub.add_parser("_protected-worker", help=argparse.SUPPRESS)
    p.add_argument("stage", choices=["kill", "hang", "traffic"])
    sub.add_parser("_export-system", help=argparse.SUPPRESS)
    sub.add_parser("_recovery-worker", help=argparse.SUPPRESS)
    p = sub.add_parser("recovery-arm")
    p.add_argument("--seconds", type=int, default=120)
    p.add_argument("--expected-ip", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--allow-happ", action="store_true")
    sub.add_parser("recovery-status")
    sub.add_parser("recovery-cancel")
    p = sub.add_parser("_watchdog", help=argparse.SUPPRESS)
    p.add_argument("journal")
    p.add_argument("descriptor", type=int)
    p.add_argument("lease", type=int)
    p.add_argument("--interactive", action="store_true")
    p = sub.add_parser("benchmark")
    p.add_argument("--aliases", nargs="+")
    p.add_argument("--ciphers", nargs="+", default=["default"])
    p.add_argument("--repeats", type=int, default=2)
    p.add_argument("--download-mib", type=int, default=8)
    p.add_argument("--upload-mib", type=int, default=2)
    p.add_argument("--transport", choices=["https", "stream"], default="https")
    p = sub.add_parser("_supervise", help=argparse.SUPPRESS)
    p.add_argument("mode")
    p.add_argument("run_id")
    args = parser.parse_args()
    try:
        if args.command == 'diagnose':
            from .diagnostics import collect
            print(json.dumps(collect(ROOT, args.output), ensure_ascii=False, indent=2))
            return 0
        if args.command == "connect":
            from .session import connect
            result = connect(ROOT)
            return 0 if result.get("cleanup", {}).get("verified") and not result.get("error") else 1
        if args.command == "cleanup-audit":
            from .protected import audit_cleanup
            result = audit_cleanup(ROOT)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['cleanup']['verified'] else 1
        if args.command == "manual-check":
            from .manual import check
            result = check(ROOT, args.duration)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['phase'] == 'awaiting_manual_reconnect' else 1
        if args.command == "_manual-worker":
            from .system import run
            run(ROOT, duration=args.duration, manual=True)
            return 0
        if args.command == "protected-check":
            from .protected import check
            check(ROOT, args.expected_ip)
            return 0
        if args.command == "_protected-worker":
            from .system import run
            run(ROOT, duration=60, self_test=args.stage != "traffic",
                protected=args.stage == "traffic", fault="hang" if args.stage == "hang" else "kill")
            return 0
        if args.command == "_recovery-worker":
            from .recovery import worker
            return worker(ROOT)
        if args.command in ("recovery-arm", "recovery-status", "recovery-cancel"):
            from .recovery import arm, status as recovery_status, cancel
            if args.command == "recovery-arm":
                result = arm(ROOT, args.seconds, args.expected_ip, args.dry_run, args.allow_happ)
            elif args.command == "recovery-cancel":
                result = cancel(ROOT)
            else:
                result = recovery_status(ROOT)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "_watchdog":
            from .system import watchdog
            watchdog(Path(args.journal), args.descriptor, args.lease, args.interactive)
            return 0
        if args.command == "_export-system":
            from .system import export
            print(json.dumps(export(ROOT)))
            return 0
        if args.command == "_supervise":
            return supervise(ROOT, args.mode, args.run_id)
        c, rules = load(ROOT), Rules.load(ROOT)
        if args.command == "start":
            if args.mode == "system":
                from .system import run, current
                from .recovery import require_acceptance
                require_acceptance()
                if not 0 <= args.duration <= 86400:
                    raise ValueError("Продолжительность должна быть от 0 до 86400 секунд")
                run(ROOT, duration=60, self_test=True)
                if not current().get("self_test_passed"):
                    raise RuntimeError("Самопроверка отката не прошла")
                run(ROOT, duration=args.duration)
                return 0
            result = start(ROOT, args.mode)
        elif args.command == "stop":
            from .system import current, request_stop
            result = request_stop(ROOT) if current()["running"] else stop(ROOT)
        elif args.command == "status":
            from .system import current
            system, transport = current(), status(ROOT)
            result = system if system.get("run_id") and not transport["running"] else transport
        elif args.command == "system-self-test":
            from .system import run, current
            run(ROOT, duration=60, self_test=True)
            result = current()
        elif args.command == "match":
            result = {"target": args.target, "outbound": "direct" if rules.direct(args.target) else "ssh"}
        elif args.command == "plan":
            result = plan(ROOT, c, rules)
        elif args.command == "server-config":
            result = server(c["remote_socks_port"])
        elif args.command == "benchmark":
            from .benchmark import run
            result = run(ROOT, args.aliases or [c['ssh_alias']], args.ciphers, args.repeats,
                         args.download_mib, args.upload_mib, args.transport)
        elif args.command == "check":
            if args.local:
                return subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT)
            if args.external:
                result = external(ROOT, c)
            else:
                executable = binary(ROOT)
                for mode in ("trial", "full", "system"):
                    target = directory(ROOT) / (mode + "-check.json")
                    write(target, client(c, rules, mode))
                    subprocess.run([executable, "check", "-c", str(target)], check=True)
                ssh_command(c, "trial")
                result = {"configurations": "ok", "ssh_profile": "ok",
                          "interactive_start": "connect_requires_terminal_and_manual_handoff",
                          "automatic_recovery": "blocked_pending_recovery_acceptance"}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if isinstance(result, dict) and (result.get("phase") == "failed" or
                                                 result.get("all_transfers_complete") is False) else 0
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        if args.command == 'connect':
            from .console import show
            show(str(error), 'error', stream=sys.stderr)
        else:
            print("Ошибка: " + str(error), file=sys.stderr)
        return 1
