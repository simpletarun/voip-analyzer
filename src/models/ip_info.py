from dataclasses import dataclass, asdict
from typing import Dict, Optional


@dataclass
class IPInfo:
    ip: str
    isp: str = "Unknown"
    org: str = "Unknown"
    city: str = "Unknown"
    country: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0
    asn: str = "N/A"
    is_ipv6: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    reverse_dns: Optional[str] = None
    score: int = 0
    classification: str = "UNKNOWN"
    confidence: float = 0.0
    cached_at: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
