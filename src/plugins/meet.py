from typing import Any, Dict

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class MeetPlugin(ProtocolPlugin):
    name = "Google Meet"
    MEET_PORTS = {19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309}

    def identify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        if self._has_meet_port(pkt):
            if intel.classification == "USER" or stats.get("inbound", 0) > 5:
                return "P2P_PEER"
            return "RELAY"
        return "UNKNOWN"

    def _has_meet_port(self, pkt: Any) -> bool:
        try:
            from scapy.all import UDP
            if pkt.haslayer(UDP):
                return pkt[UDP].sport in self.MEET_PORTS or pkt[UDP].dport in self.MEET_PORTS
        except Exception:
            pass
        return False

    def describe(self, pkt: Any) -> str:
        if self._has_meet_port(pkt):
            return "Google-Meet"
        return "Unknown"
