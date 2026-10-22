"""Генерация конфигураций поддерживаемого sing-box."""

import ipaddress
import json
import re
import subprocess
from pathlib import Path

VERSION = "1.14.3"
ARCHIVE_SHA256 = "0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5"
CIPHERS = ("default", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com")


def load(root):
    path = root / "config.json"
    if not path.exists():
        path = root / "config.example.json"
    c = json.loads(path.read_text(encoding="utf-8"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", c["ssh_alias"]) or c["ssh_alias"].startswith("-"):
        raise ValueError("Некорректный SSH-алиас")
    if not re.fullmatch(r"en[0-9]+", c["physical_interface"]):
        raise ValueError("Нужен физический интерфейс enN")
    ports = [c[k] for k in ("listen_port", "forward_port", "dns_port", "remote_socks_port")]
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(set(ports)) != 4:
        raise ValueError("Нужны разные непривилегированные порты")
    for k in ("dns_direct", "dns_tunnel"):
        if k != "dns_direct" or c[k] != "dhcp":
            ipaddress.ip_address(c[k])
    if type(c["backend_ready"]) is not bool:
        raise ValueError("backend_ready должен быть логическим значением")
    if not 0 <= c["max_restarts"] <= 10 or not 1 <= c["connect_timeout"] <= 60:
        raise ValueError("Некорректные пределы переподключения")
    c.setdefault("ssh_cipher", "default")
    if c["ssh_cipher"] not in CIPHERS:
        raise ValueError("Неподдерживаемый SSH-шифр")
    return c


def physical_dns(interface):
    try:
        text = subprocess.check_output(["/usr/sbin/ipconfig", "getoption", interface, "domain_name_server"],
                                       text=True, encoding="utf-8", stderr=subprocess.DEVNULL, timeout=3)
        addresses = [str(ipaddress.IPv4Address(value)) for value in text.split()]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise RuntimeError("DNS физической сети по DHCP недоступен; укажите dns_direct явно") from error
    if not addresses:
        raise RuntimeError("DHCP не сообщил DNS физической сети")
    return addresses[0]


def client(c, rules, mode="trial", interface=None, dns_ports=None):
    physical = interface or c["physical_interface"]
    direct = {"type": "direct", "tag": "direct", "bind_interface": physical,
              "domain_resolver": "dns-direct", "connect_timeout": "10s"}
    proxy = {"type": "socks", "tag": "ssh", "server": "127.0.0.1",
             "server_port": c["forward_port"], "version": "5", "bind_interface": "lo0",
             "connect_timeout": "10s"}
    if mode == "trial":
        proxy["network"] = "tcp"
    else:
        proxy["udp_over_tcp"] = {"enabled": True, "version": 2}
    servers = []
    for tag, key in (("dns-direct", "dns_direct"), ("dns-ssh", "dns_tunnel")):
        address = physical_dns(physical) if key == "dns_direct" and c[key] == "dhcp" else c[key]
        server = {"type": "udp" if tag == "dns-direct" else "tcp", "tag": tag,
                  "server": address, "server_port": (dns_ports or {}).get(tag, 53)}
        if tag == "dns-direct":
            server["bind_interface"] = physical
        else:
            server["detour"] = "ssh"
        servers.append(server)
    inbounds = [{"type": "socks", "tag": "local", "listen": "127.0.0.1",
                 "listen_port": c["listen_port"]},
                {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
                 "listen_port": c["dns_port"]}]
    if mode == "system":
        inbounds.append({"type": "tun", "tag": "system", "interface_name": "utun99",
                         "address": ["172.31.255.1/30", "fd7a:9b3c:53::1/126"],
                         "mtu": 1400, "auto_route": False, "dns_mode": "disabled"})
        servers.append({"type": "fakeip", "tag": "dns-fake",
                        "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"})
    route_rules = [{"inbound": ["dns-in"], "action": "hijack-dns"},
                   {"port": 53, "action": "hijack-dns"}]
    if mode == "trial":
        route_rules.append({"network": "udp", "action": "reject"})
    route_rules.append({"type": "logical", "mode": "and", "rules": [
        {"network": "tcp"}, {"domain_regex": [".+"], "invert": True}],
        "action": "sniff", "sniffer": ["http", "tls"], "timeout": "300ms"})
    if rules.domains:
        route_rules.append({"domain_suffix": rules.domains, "action": "route", "outbound": "direct"})
    if rules.cidrs:
        route_rules.append({"ip_cidr": rules.cidrs, "action": "route", "outbound": "direct"})
    dns_rules = []
    if rules.domains:
        dns_rules.append({"domain_suffix": rules.domains, "action": "route", "server": "dns-direct"})
    if mode == "system":
        # Временные адреса сохраняют связь с доменом для маршрутизации TUN.
        dns_rules.insert(0, {"query_type": ["A", "AAAA"], "action": "route", "server": "dns-fake",
                            "rewrite_ttl": 1})
    return {"log": {"level": "warn", "timestamp": True},
            "dns": {"servers": servers, "rules": dns_rules, "final": "dns-ssh",
                    "reverse_mapping": True, "strategy": "prefer_ipv4"},
            "inbounds": inbounds, "outbounds": [direct, proxy],
            "route": {"rules": route_rules, "final": "ssh", "default_domain_resolver": "dns-ssh"}}


def server(port):
    return {"log": {"level": "warn", "timestamp": True},
            "inbounds": [{"type": "socks", "tag": "backend", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [{"type": "direct", "tag": "egress"}], "route": {"final": "egress"}}


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    Path(path).chmod(0o600)
