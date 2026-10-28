from abc import ABC, abstractmethod


class Exporter(ABC):
    @abstractmethod
    def export(self, report: object, peers: dict[str, dict], path: str) -> bool:
        ...
