from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional


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
    abuse_score: Optional[int] = None
    fraud_score: Optional[int] = None
    is_vpn: bool = False
    is_tor: bool = False
    open_ports: list = field(default_factory=list)
    enrichment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
