from typing import Any, Dict

from src.models.ip_info import IPInfo


class ProtocolPlugin:
    name: str = "Generic"

    def identify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        return "UNKNOWN"

    def describe(self, pkt: Any) -> str:
        return "Unknown"
