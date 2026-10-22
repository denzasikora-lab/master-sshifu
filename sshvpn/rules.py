"""Разбор локальных правил с точными границами доменов."""

import ipaddress
import re
from pathlib import Path


def domain(value):
    """Преобразовать домен в проверенную ASCII-форму.

    Parameters
    ----------
    value : str
        Домен без схемы, порта и пути.

    Returns
    -------
    str
        Домен в нижнем регистре с IDNA-представлением.
    """
    value = value.strip().lstrip(".").rstrip(".").lower()
    if not value or any(c in value for c in "/:@* "):
        raise ValueError("Некорректный домен")
    value = value.encode("idna").decode("ascii")
    if len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
        for p in value.split(".")
    ):
        raise ValueError("Некорректный домен")
    return value


def lines(path):
    return [s.split("#", 1)[0].strip() for s in Path(path).read_text(encoding="utf-8").splitlines()
            if s.split("#", 1)[0].strip()]


class Rules:
    def __init__(self, domains, cidrs):
        self.domains = sorted(set(domain(s) for s in domains))
        self.cidrs = sorted(set(str(ipaddress.ip_network(s, strict=False)) for s in cidrs))

    @classmethod
    def load(cls, root):
        domains = lines(root / 'rules/direct-domains.txt')
        cidrs = lines(root / 'rules/direct-cidrs.txt')
        for name, target in (('local-domains.txt', domains), ('local-cidrs.txt', cidrs)):
            path = root / 'rules' / name
            if path.exists():
                target.extend(lines(path))
        return cls(domains, cidrs)

    def direct(self, target):
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            name = domain(target)
            return any(name == item or name.endswith("." + item) for item in self.domains)
        return any(address in ipaddress.ip_network(item) for item in self.cidrs)
