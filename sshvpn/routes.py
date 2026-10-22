"""Журнал владения маршрутами для модели ядра и исполнителя macOS.

Команды изменения маршрутов находятся в system.MacRoutes. Изолированные
проверки журнала не заменяют приемку реального системного отката.
"""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Route:
    prefix: str
    interface: str
    gateway: str = ""


class Journal:
    def __init__(self, kernel, save):
        self.kernel, self.save = kernel, save
        self.entries = []

    def add(self, route):
        if self.kernel.get(route.prefix) is not None:
            raise RuntimeError("Маршрут уже существует; замена запрещена")
        entry = {"route": asdict(route), "phase": "intent"}
        self.entries.append(entry)
        self.save(self.entries)
        self.kernel.add(route)
        entry["phase"] = "owned"
        self.save(self.entries)

    def rollback(self):
        conflicts = []
        for entry in reversed(self.entries):
            route = Route(**entry["route"])
            current = self.kernel.get(route.prefix)
            if entry["phase"] == "removed":
                continue
            if entry["phase"] == "owned" and current == route:
                self.kernel.delete(route)
                entry["phase"] = "removed"
            elif current is None:
                entry["phase"] = "removed"
            else:
                conflicts.append(route.prefix)
            self.save(self.entries)
        return conflicts
