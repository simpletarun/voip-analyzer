from dataclasses import dataclass


@dataclass(frozen=True)
class PacketInfo:
    id: int
    time: str
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    length: int
    peer: str
    direction: str
    ip_type: str
    ver: int
    isp: str
    city: str
    country: str
    lat: float
    lon: float
    is_stun: bool = False
    protocol_name: str = "Unknown"
