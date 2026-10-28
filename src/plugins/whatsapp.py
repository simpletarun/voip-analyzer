import ipaddress
from typing import Any

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class WhatsAppPlugin(ProtocolPlugin):
    name = "WhatsApp"
    STUN_MAGIC = 0x2112A442

    def __init__(self) -> None:
        # RTP is only reported after two packets prove a sequence, so random
        # encrypted UDP is never mislabelled as RTP.
        self._rtp_state: dict = {}
        self._max_rtp_flows = 4096

    _RTP_STATIC_PT = set(range(0, 35)) | set(range(96, 128))

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
        """Return a real protocol name, or the transport when unidentifiable."""
        from scapy.all import Raw, TCP, UDP

        payload = b""
        sport = dport = 0
        udp = tcp = False
        try:
            if pkt.haslayer(UDP):
                udp = True
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            elif pkt.haslayer(TCP):
                tcp = True
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
        except Exception:
            pass
        ports = {sport, dport}
        first = payload[0] if payload else -1

        # STUN / TURN share the magic cookie; the method tells them apart.
        if len(payload) >= 8 and int.from_bytes(payload[4:8], "big") == self.STUN_MAGIC:
            m = int.from_bytes(payload[0:2], "big")
            method = ((m & 0x000F) | ((m & 0x00E0) >> 1)
                      | ((m & 0x3E00) >> 2))
            return "TURN" if method in (0x003, 0x004, 0x006, 0x007, 0x008, 0x009) else "STUN"

        if udp and len(payload) >= 3 and 20 <= first <= 23 and payload[1] == 0xFE:
            return "DTLS"

        if udp and len(payload) >= 5 and first & 0x80:
            version = int.from_bytes(payload[1:5], "big")
            if version in (1, 0x6B3343CF):
                return "QUIC"

        if tcp and payload[:2] == b"\x16\x03":
            return "TLS"
        first_line = payload.split(b"\r\n", 1)[0][:200].lower()
        if first_line.startswith(b"sip/2.0") or (
                first_line.split(b" ", 1)[0] in (
                    b"invite", b"register", b"options", b"bye", b"cancel",
                    b"ack", b"prack", b"subscribe", b"notify")
                and b"sip:" in first_line):
            return "SIP"
        if tcp and (b" http/" in first_line[:40] or first_line.startswith(b"http/")):
            return "HTTP"

        rtp = self._rtp(pkt, payload, udp, sport, dport)
        if rtp:
            return rtp

        if 53 in ports:
            return "DNS" if 5353 not in ports else "MDNS"
        if 5353 in ports:
            return "MDNS"
        if 5355 in ports:
            return "LLMNR"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 500 in ports or 4500 in ports:
            return "IKE"
        if 1900 in ports and (b"M-SEARCH" in payload or b"NOTIFY" in payload):
            return "SSDP"
        if udp:
            return "UDP"
        if tcp:
            return "TCP"
        return "OTHER"

    def _rtp(self, pkt: Any, payload: bytes, udp: bool,
             sport: int, dport: int) -> str | None:
        if not udp or len(payload) < 12 or payload[0] & 0xC0 != 0x80:
            return None
        if 192 <= payload[1] <= 223:
            if len(payload) >= 8:
                # RTCP length field: 32-bit words minus one; validates the packet
                words = int.from_bytes(payload[2:4], "big") + 1
                if words * 4 <= len(payload):
                    return "RTCP"
            return None
        # Validate the RTP header (including optional CSRC/extension) so
        # random encrypted UDP can't masquerade as RTP.
        csrc = payload[0] & 0x0F
        has_ext = bool(payload[0] & 0x10)
        header_len = 12 + 4 * csrc
        if len(payload) < header_len + 4:
            return None
        if has_ext:
            ext_len = int.from_bytes(payload[header_len + 2:header_len + 4], "big") * 4
            if len(payload) < header_len + 4 + ext_len:
                return None
        if (payload[1] & 0x7F) not in self._RTP_STATIC_PT:
            return None
        try:
            from scapy.all import IP, IPv6
            if pkt.haslayer(IP):
                key = (pkt[IP].src, sport, pkt[IP].dst, dport)
            elif pkt.haslayer(IPv6):
                key = (pkt[IPv6].src, sport, pkt[IPv6].dst, dport)
            else:
                return None
        except Exception:
            return None
        seq = int.from_bytes(payload[2:4], "big")
        ssrc = payload[8:12]
        prev = self._rtp_state.get(key)
        if len(self._rtp_state) > self._max_rtp_flows:
            self._rtp_state.clear()
        self._rtp_state[key] = (seq, ssrc)
        if prev and prev[1] == ssrc and seq == (prev[0] + 1) & 0xFFFF:
            return "RTP"
        return None
