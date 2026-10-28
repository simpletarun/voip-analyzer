import ipaddress

from src.services.stun import MAGIC, describe, parse_stun


def _xor_address(ip: str, port: int, tid: bytes) -> bytes:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        key = MAGIC
        family = 0x01
    else:
        key = MAGIC + tid
        family = 0x02
    raw = bytes(a ^ b for a, b in zip(addr.packed, key))
    return b"\x00" + bytes([family]) + (port ^ 0x2112).to_bytes(2, "big") + raw


def _plain_address(ip: str, port: int) -> bytes:
    addr = ipaddress.ip_address(ip)
    family = 0x01 if addr.version == 4 else 0x02
    return b"\x00" + bytes([family]) + port.to_bytes(2, "big") + addr.packed


def _attr(kind: int, value: bytes) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value + b"\x00" * pad


def _message(attrs: bytes, mtype: int = 0x0101) -> bytes:
    tid = b"0123456789ab"
    body = attrs
    return (mtype.to_bytes(2, "big") + len(body).to_bytes(2, "big")
            + MAGIC + tid + body), tid


def test_parse_xor_mapped_ipv4():
    tid = b"0123456789ab"
    msg, _ = _message(_attr(0x0020, _xor_address("203.0.113.9", 50000, tid)))
    info = parse_stun(msg)
    assert info is not None
    assert info["addresses"] == [("203.0.113.9", 50000, "mapped")]


def test_parse_peer_relayed_and_text():
    tid = b"0123456789ab"
    attrs = (
        _attr(0x0012, _xor_address("198.51.100.7", 1234, tid))
        + _attr(0x0016, _xor_address("192.0.2.10", 3478, tid))
        + _attr(0x0006, b"alice:bob")
        + _attr(0x8022, b"Telegram")
    )
    msg, _ = _message(attrs)
    info = parse_stun(msg)
    assert info["addresses"] == [
        ("198.51.100.7", 1234, "peer"),
        ("192.0.2.10", 3478, "relayed"),
    ]
    assert info["username"] == "alice:bob"
    assert info["software"] == "Telegram"


def test_parse_xor_mapped_ipv6():
    tid = b"0123456789ab"
    msg, _ = _message(_attr(0x0020, _xor_address("2001:db8::5", 40000, tid)))
    info = parse_stun(msg)
    assert info["addresses"] == [("2001:db8::5", 40000, "mapped")]


def test_plain_mapped_address():
    msg, _ = _message(_attr(0x0001, _plain_address("203.0.113.11", 6000)))
    info = parse_stun(msg)
    assert info["addresses"] == [("203.0.113.11", 6000, "mapped")]


def test_rejects_non_stun_and_truncated():
    assert parse_stun(b"") is None
    assert parse_stun(b"\x00" * 19) is None
    assert parse_stun(b"\x00\x01\x00\x00" + b"\x00" * 16) is None


def test_describe_hides_mapped_and_self():
    tid = b"0123456789ab"
    attrs = (
        _attr(0x0020, _xor_address("203.0.113.9", 50000, tid))
        + _attr(0x0012, _xor_address("198.51.100.7", 1234, tid))
        + _attr(0x8022, b"Telegram")
    )
    msg, _ = _message(attrs)
    info = parse_stun(msg)
    text = describe(info, skip={"10.0.0.1"})
    assert "203.0.113.9" not in text
    assert "peer 198.51.100.7:1234" in text
    assert "Telegram" in text
    assert describe(info, skip={"198.51.100.7"}) == "Telegram"
