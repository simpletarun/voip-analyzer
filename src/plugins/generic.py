from typing import Any

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class GenericPlugin(ProtocolPlugin):
    name = "Generic"

    def identify(self, pkt: Any, peer: str, stats: dict, intel: IPInfo) -> str:
        return intel.classification
