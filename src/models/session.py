from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SessionReport:
    id: Optional[int] = None
    timestamp: str = ""
    duration_seconds: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    p2p_count: int = 0
    relay_count: int = 0
    unknown_count: int = 0
    countries: List[str] = field(default_factory=list)
    protocol: str = "WhatsApp"
    notes: str = ""
