"""Minimal STUN (RFC 5389 / RFC 8489) parser.

Used to recover the real peer/relay endpoints carried inside STUN and TURN
packets, which is how Wireshark reveals call participants:

* XOR-PEER-ADDRESS     - remote user inside a TURN Send/Data indication
* XOR-RELAYED-ADDRESS  - TURN relay endpoint
* XOR-MAPPED-ADDRESS   - reflexive address (often our own, so not shown)
"""

import ipaddress

MAGIC = b"\x21\x12\xa4\x42"

_XOR_ATTRS = {0x0012: "peer", 0x0016: "relayed", 0x0020: "mapped"}
_PLAIN_ATTRS = {0x0001: "mapped"}
_TEXT_ATTRS = {0x0006: "username", 0x8022: "software"}


def _address(value: bytes, xor: bool, tid: bytes) -> tuple[str, int] | None:
    if len(value) < 8:
        return None
    family = value[1]
    port = int.from_bytes(value[2:4], "big")
    if xor:
        port ^= 0x2112
    if family == 0x01:
        raw = value[4:8]
        if xor:
            raw = bytes(a ^ b for a, b in zip(raw, MAGIC))
        try:
            return str(ipaddress.IPv4Address(raw)), port
        except ValueError:
            return None
    if family == 0x02 and len(value) >= 20:
        raw = value[4:20]
        if xor:
            key = MAGIC + tid
            raw = bytes(a ^ b for a, b in zip(raw, key))
        try:
            return str(ipaddress.IPv6Address(raw)), port
        except ValueError:
            return None
    return None


def parse_stun(payload: bytes) -> dict | None:
    """Return a summary of a STUN/TURN message, or None if not STUN."""
    if len(payload) < 20 or payload[4:8] != MAGIC:
        return None
    mlen = int.from_bytes(payload[2:4], "big")
    tid = payload[8:20]
    end = min(20 + mlen, len(payload))
    info: dict = {
        "message_type": int.from_bytes(payload[0:2], "big"),
        "username": None,
        "software": None,
        "addresses": [],
    }
    offset = 20
    while offset + 4 <= end:
        attr = int.from_bytes(payload[offset:offset + 2], "big")
        alen = int.from_bytes(payload[offset + 2:offset + 4], "big")
        value = payload[offset + 4:offset + 4 + alen]
        offset += 4 + ((alen + 3) // 4) * 4
        if attr in _TEXT_ATTRS:
            text = value.decode("utf-8", "replace").strip("\x00").strip()
            if text:
                info[_TEXT_ATTRS[attr]] = text[:80]
        elif attr in _XOR_ATTRS:
            addr = _address(value, True, tid)
            if addr:
                info["addresses"].append((addr[0], addr[1], _XOR_ATTRS[attr]))
        elif attr in _PLAIN_ATTRS:
            addr = _address(value, False, tid)
            if addr:
                info["addresses"].append((addr[0], addr[1], _PLAIN_ATTRS[attr]))
    return info


def describe(info: dict | None, skip: set[str] | None = None) -> str:
    """Short single-line summary for the packet table (never the local host)."""
    if not info:
        return ""
    skip = skip or set()
    parts = []
    for ip, port, kind in info.get("addresses", []):
        # XOR-MAPPED-ADDRESS is usually this machine's own public endpoint.
        if kind == "mapped" or ip in skip:
            continue
        parts.append(f"{kind} {ip}:{port}")
    if info.get("software"):
        parts.append(info["software"])
    if info.get("username"):
        parts.append(f"user={info['username']}")
    return " | ".join(parts[:3])
