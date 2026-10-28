"""Tests for WhatsApp plugin peer confidence scoring."""
import pytest

from src.models.ip_info import IPInfo
from src.plugins.whatsapp import WhatsAppPlugin


def _make_intel(**kwargs) -> IPInfo:
    defaults = {"ip": "1.2.3.4", "is_ipv6": False, "isp": "Airtel",
                "country": "India", "is_mobile": True}
    defaults.update(kwargs)
    return IPInfo(**defaults)


def test_peer_confidence_zero_total():
    stats = {"packets": 0, "inbound": 0, "outbound": 0, "stun": 0}
    score = WhatsAppPlugin.peer_confidence(_make_intel(), stats)
    assert score == 0


def test_peer_confidence_stun_bonus():
    stats = {"packets": 10, "inbound": 5, "outbound": 5, "stun": 2}
    intel = _make_intel(is_mobile=True, is_hosting=False, is_proxy=False)
    score = WhatsAppPlugin.peer_confidence(intel, stats)
    assert score >= 35


def test_peer_confidence_high_ratio():
    stats = {"packets": 10, "inbound": 8, "outbound": 2, "stun": 1}
    intel = _make_intel(is_mobile=False, is_hosting=False, is_proxy=False)
    score = WhatsAppPlugin.peer_confidence(intel, stats)
    assert score > 0


def test_peer_confidence_hosting_penalty():
    stats = {"packets": 3, "inbound": 1, "outbound": 2, "stun": 0}
    intel = _make_intel(is_mobile=False, is_hosting=True, is_proxy=False,
                        isp="Unknown", country="Unknown")
    score = WhatsAppPlugin.peer_confidence(intel, stats)
    assert score < 20


def test_is_noise_ip_private():
    assert WhatsAppPlugin.is_noise_ip("192.168.1.1") is True


def test_is_noise_ip_multicast():
    assert WhatsAppPlugin.is_noise_ip("224.0.0.1") is True


def test_is_noise_ip_broadcast():
    assert WhatsAppPlugin.is_noise_ip("255.255.255.255") is True


def test_is_noise_ip_cgnat():
    assert WhatsAppPlugin.is_noise_ip("100.64.0.1") is True


def test_is_noise_ip_public():
    assert WhatsAppPlugin.is_noise_ip("8.8.8.8") is False


def test_is_noise_ip_empty():
    assert WhatsAppPlugin.is_noise_ip("") is True


def _describe(proto, payload, sport=50000, dport=50001):
    pytest.importorskip("scapy.all")
    from scapy.all import IP, Raw
    pkt = IP(src="1.2.3.4", dst="5.6.7.8") / proto(sport=sport, dport=dport)
    if payload:
        pkt = pkt / Raw(payload)
    return WhatsAppPlugin().describe(pkt)


def test_describe_stun():
    from scapy.all import UDP
    body = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"abcdefghijkl"
    assert _describe(UDP, body, dport=3478) == "STUN"


def test_describe_dtls():
    from scapy.all import UDP
    assert _describe(UDP, b"\x16\xfe\xfd\x00\x01", dport=5349) == "DTLS"


def test_describe_tls():
    from scapy.all import TCP
    assert _describe(TCP, b"\x16\x03\x01\x00\x05", dport=443) == "TLS"


def test_describe_dns_and_ntp():
    from scapy.all import UDP
    assert _describe(UDP, b"\x12\x34", sport=52000, dport=53) == "DNS"
    assert _describe(UDP, b"\x1b\x00", sport=52000, dport=123) == "NTP"


def test_describe_plain_transport():
    from scapy.all import TCP, UDP
    assert _describe(UDP, b"\xde\xad\xbe\xef") == "UDP"
    assert _describe(TCP, b"\xde\xad\xbe\xef") == "TCP"
    assert _describe(UDP, b"") == "UDP"


def test_describe_turn():
    from scapy.all import UDP
    body = b"\x00\x03\x00\x00\x21\x12\xa4\x42" + b"abcdefghijkl"
    assert _describe(UDP, body, dport=3478) == "TURN"


def test_describe_sip():
    from scapy.all import UDP
    payload = b"INVITE sip:bob@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP x\r\n\r\n"
    assert _describe(UDP, payload, dport=5060) == "SIP"


def test_describe_quic_long_header():
    from scapy.all import UDP
    payload = b"\xc0\x00\x00\x00\x01" + b"\x00" * 1200
    assert _describe(UDP, payload, dport=443) == "QUIC"


def _rtp_packet(seq, ssrc=b"\x01\x02\x03\x04", pt=111):
    header = bytes([0x80, pt]) + seq.to_bytes(2, "big") + b"\x00\x00\x00\x01" + ssrc
    return header + b"\x00" * 8


def test_rtp_requires_sequence_confirmation():
    from scapy.all import IP, Raw, UDP
    plugin = WhatsAppPlugin()
    first = IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=50000, dport=50001)
    second = IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=50000, dport=50001)
    assert plugin.describe(first / Raw(_rtp_packet(100))) == "UDP"
    assert plugin.describe(second / Raw(_rtp_packet(101))) == "RTP"


def test_rtcp_detected_directly():
    from scapy.all import UDP
    # RTCP packet type 200 (Sender Report), version 2
    payload = bytes([0x80, 200]) + b"\x00" * 10
    assert _describe(UDP, payload) == "RTCP"
