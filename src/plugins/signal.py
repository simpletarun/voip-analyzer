from typing import Any, Dict

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class SignalPlugin(ProtocolPlugin):
    name = "Signal"
    SIGNAL_PORTS = {8043, 8044, 8045, 8046}

    def identify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        if self._has_signal_port(pkt):
            if intel.classification == "USER":
                return "P2P_PEER"
            return "RELAY"
        return "UNKNOWN"

    def _has_signal_port(self, pkt: Any) -> bool:
        try:
            from scapy.all import TCP, UDP
            if pkt.haslayer(UDP):
                return pkt[UDP].sport in self.SIGNAL_PORTS or pkt[UDP].dport in self.SIGNAL_PORTS
            if pkt.haslayer(TCP):
                return pkt[TCP].sport in self.SIGNAL_PORTS or pkt[TCP].dport in self.SIGNAL_PORTS
        except Exception:
            pass
        return False

    def describe(self, pkt: Any) -> str:
        if self._has_signal_port(pkt):
            return "Signal"
        return "Unknown"
