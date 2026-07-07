import ipaddress
from typing import Any

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class WhatsAppPlugin(ProtocolPlugin):
    name = "WhatsApp"
    STUN_MAGIC = 0x2112A442

    @staticmethod
    def is_noise_ip(ip: str) -> bool:
        if not ip:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_multicast or addr.is_loopback or addr.is_link_local:
                return True
            if addr.is_reserved:
                return True
            if addr.is_private:
                return True
        except ValueError:
            pass
        if ip.startswith(("224.", "225.", "226.", "227.", "228.", "229.",
                          "230.", "231.", "232.", "233.", "234.", "235.",
                          "236.", "237.", "238.", "239.")):
            return True
        if ip == "255.255.255.255":
            return True
        if ip.startswith("ff0") or ip.startswith("ff"):
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_multicast:
                    return True
            except ValueError:
                pass
        if ip.startswith("100."):
            try:
                first_octet = int(ip.split(".")[0])
                second_octet = int(ip.split(".")[1])
                if first_octet == 100 and 64 <= second_octet <= 127:
                    return True
            except (ValueError, IndexError):
                pass
        return False

    @staticmethod
    def peer_confidence(intel: IPInfo, stats: dict) -> int:
        score = 0
        inb = stats.get("inbound", 0)
        outb = stats.get("outbound", 0)
        pkts = stats.get("packets", 0)
        stun = stats.get("stun", 0)
        total = inb + outb
        if total == 0:
            return 0
        bids = min(inb, outb)
        ratio = bids / max(total, 1)
        if pkts >= 5 and stun > 0:
            score += 35
        if ratio > 0.3:
            score += 25
        if pkts >= 20:
            score += 15
        if stun >= 3:
            score += 10
        if intel.is_mobile:
            score += 20
        if intel.is_hosting or intel.is_proxy:
            score -= 30
        if not intel.is_mobile and not intel.is_hosting and not intel.is_proxy:
            if intel.isp and intel.isp not in ("Unknown", ""):
                score += 5
        if intel.country and intel.country not in ("Unknown", ""):
            score += 10
        if intel.isp and intel.isp not in ("Unknown", ""):
            score += 5
        if intel.is_ipv6:
            score += 5
        return max(0, min(100, score))

    def identify(self, pkt: Any, peer: str, stats: dict, intel: IPInfo) -> str:
        if self.is_noise_ip(peer):
            return "UNKNOWN"
        inb = stats.get("inbound", 0)
        outb = stats.get("outbound", 0)
        pkts = stats.get("packets", 0)
        stun = stats.get("stun", 0)
        if inb > 3 and outb > 3 and stun > 0:
            return "P2P_PEER"
        if intel.classification == "RELAY" and intel.confidence > 0.6:
            return "RELAY"
        if intel.classification == "P2P_PEER" and intel.confidence > 0.4:
            return "P2P_PEER"
        if pkts > 50 and intel.score > 20:
            return "RELAY"
        if pkts < 5:
            return "UNKNOWN"
        return intel.classification

    def describe(self, pkt: Any) -> str:
        try:
            from scapy.all import Raw
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                if len(payload) >= 8:
                    magic = int.from_bytes(payload[4:8], "big")
                    if magic == self.STUN_MAGIC:
                        return "STUN"
        except Exception:
            pass
        return "WhatsApp-VoIP"
