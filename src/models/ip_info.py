from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class IPInfo:
    ip: str
    isp: str = "Unknown"
    org: str = "Unknown"
    city: str = "Unknown"
    country: str = "Unknown"
    continent: str = ""
    continent_code: str = ""
    country_code: str = ""
    region_code: str = ""
    region_name: str = ""
    district: str = ""
    zip: str = ""
    timezone: str = ""
    offset: int = 0
    currency: str = ""
    asname: str = ""
    lat: float = 0.0
    lon: float = 0.0
    asn: str = "N/A"
    is_ipv6: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    reverse_dns: str | None = None
    score: int = 0
    classification: str = "UNKNOWN"
    confidence: float = 0.0
    cached_at: str | None = None
    abuse_score: int | None = None
    fraud_score: int | None = None
    is_vpn: bool = False
    is_tor: bool = False
    open_ports: list = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
