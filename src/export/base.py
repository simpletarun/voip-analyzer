from abc import ABC, abstractmethod
from typing import Dict


class Exporter(ABC):
    @abstractmethod
    def export(self, report: object, peers: Dict[str, Dict], path: str) -> bool:
        ...
