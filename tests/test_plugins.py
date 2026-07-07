"""Tests for WhatsApp plugin peer confidence scoring."""
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
