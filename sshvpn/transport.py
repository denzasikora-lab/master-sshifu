"""OpenSSH со строгой проверкой ключа и без изменения пользовательских файлов."""

import ipaddress
import os
import subprocess


def profile(alias):
    result = subprocess.run(["/usr/bin/ssh", "-G", alias], check=True, text=True,
                            encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    values = {}
    for line in result.stdout.splitlines():
        k, _, v = line.partition(" ")
        values.setdefault(k, []).append(v)
    for name in ("proxycommand", "proxyjump", "remotecommand"):
        if values.get(name, ["none"])[0] != "none":
            raise ValueError("Профили с ProxyCommand, ProxyJump или RemoteCommand требуют отдельной проверки")
    ipaddress.ip_address(values["hostname"][0])
    return values


def ssh_command(c, mode, p=None):
    p = p or profile(c["ssh_alias"])
    args = ["/usr/bin/ssh", "-F", "/dev/null", "-N", "-T", "-n"]
    options = {"BatchMode": "yes", "StrictHostKeyChecking": "yes", "UpdateHostKeys": "no",
               "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
               "PreferredAuthentications": "publickey", "ForwardAgent": "no", "ForwardX11": "no",
               "IdentitiesOnly": "yes", "ExitOnForwardFailure": "yes", "ControlMaster": "no",
               "ControlPath": "none", "ControlPersist": "no", "PermitLocalCommand": "no",
               "ServerAliveInterval": "10", "ServerAliveCountMax": "3",
               "ConnectTimeout": str(c["connect_timeout"]), "ConnectionAttempts": "1", "LogLevel": "ERROR",
               "Compression": "no"}
    if c.get("ssh_cipher", "default") != "default":
        options["Ciphers"] = c["ssh_cipher"]
    if mode != "trial":
        options["BindInterface"] = c["physical_interface"]
    for key, option in (("userknownhostsfile", "UserKnownHostsFile"),
                        ("hostkeyalias", "HostKeyAlias"), ("identityagent", "IdentityAgent")):
        if key in p:
            options[option] = p[key][0]
    for key, value in options.items():
        args += ["-o", f"{key}={value}"]
    for path in p.get("identityfile", []):
        path = os.path.expanduser(path.replace("%d", os.path.expanduser("~")))
        if "%" in path:
            raise ValueError("Сложные шаблоны IdentityFile требуют отдельной проверки")
        args += ["-i", path]
    args += ["-p", p["port"][0], "-l", p["user"][0]]
    if mode == "trial":
        args += ["-D", f"127.0.0.1:{c['forward_port']}"]
    else:
        args += ["-L", f"127.0.0.1:{c['forward_port']}:127.0.0.1:{c['remote_socks_port']}"]
    return args + [p["hostname"][0]]
