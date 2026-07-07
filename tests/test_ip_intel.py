"""Tests for IPIntelligence scoring algorithm."""
import pytest
from src.models.ip_info import IPInfo
from src.services.ip_intel import IPIntelligence


def _make_intel() -> IPIntelligence:
    inst = object.__new__(IPIntelligence)
    inst.cache = None
    inst.config = None
    inst.memory_cache = {}
    inst._lock = __import__("threading").Lock()
    inst._calls = []
    return inst


def _make_info(**kwargs) -> IPInfo:
    defaults = {"ip": "1.2.3.4", "is_ipv6": False}
    defaults.update(kwargs)
    return IPInfo(**defaults)


def test_minimal_ip_v4():
    svc = _make_intel()
    info = svc._minimal("8.8.8.8")
    assert info.ip == "8.8.8.8"
    assert info.is_ipv6 is False
    assert info.classification == "UNKNOWN"


def test_minimal_ip_v6():
    svc = _make_intel()
    info = svc._minimal("2001:4860:4860::8888")
    assert info.ip == "2001:4860:4860::8888"
    assert info.is_ipv6 is True


def test_score_hosting():
    svc = _make_intel()
    info = _make_info(is_hosting=True, is_mobile=False, is_proxy=False)
    svc._calculate_score(info)
    assert info.score >= 50
    assert info.classification == "RELAY"


def test_score_proxy():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=False, is_proxy=True)
    svc._calculate_score(info)
    assert info.score >= 40
    assert info.classification == "RELAY"


def test_score_mobile():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=True, is_proxy=False, isp="Airtel", org="")
    svc._calculate_score(info)
    assert info.score < 0
    assert info.classification == "P2P_PEER"


def test_score_cloud_asn():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=False, is_proxy=False,
                      asn="AS15169", org="")
    svc._calculate_score(info)
    assert "RELAY" in info.classification or info.score > 30


def test_score_cloud_org():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=False, is_proxy=False,
                      asn="N/A", org="Amazon AWS")
    svc._calculate_score(info)
    assert info.score > 20


def test_score_unknown_isp():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=False, is_proxy=False,
                      asn="N/A", org="", isp="Unknown")
    svc._calculate_score(info)
    assert info.classification in ("P2P_PEER", "UNKNOWN")
    assert info.confidence > 0


def test_score_known_isp_not_hosting():
    svc = _make_intel()
    info = _make_info(is_hosting=False, is_mobile=False, is_proxy=False,
                      asn="N/A", org="", isp="Bharti Airtel",
                      country="India")
    svc._calculate_score(info)
    assert info.score <= -10 or info.classification == "P2P_PEER"
