from typing import Any, Dict

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class TelegramPlugin(ProtocolPlugin):
    name = "Telegram"
    TG_PORTS = {443, 8080}

    def identify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        try:
            from scapy.all import Raw, TCP
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport in self.TG_PORTS:
                    inb = stats.get("inbound", 0)
                    outb = stats.get("outbound", 0)
                    if inb > 10 and outb > 10:
                        return "P2P_PEER"
                    if intel.is_hosting:
                        return "RELAY"
        except Exception:
            pass
        return "UNKNOWN"

    def describe(self, pkt: Any) -> str:
        try:
            from scapy.all import Raw, TCP
            if pkt.haslayer(TCP) and pkt[TCP].dport in self.TG_PORTS:
                if pkt.haslayer(Raw):
                    return "Telegram-DC"
        except Exception:
            pass
        return "Unknown"
