"""IPQualityScore enrichment.

Requires ``IPQS_API_KEY``. Returns VPN/proxy/Tor detection, ASN, ISP, hosting
and an overall fraud score (0-100).
"""

import logging
import os

from src.enrichment.base import EnrichmentPlugin
from src.utils.errors import ValidationError
from src.utils.http import build_session
from src.utils.validation import validate_ip

logger = logging.getLogger(__name__)

IPQS_URL = "https://www.ipqualityscore.com/api/json/ip/{key}/{ip}"


class IPQualityScorePlugin(EnrichmentPlugin):
    name = "ipqualityscore"
    version = "1.0.0"
    description = "IPQualityScore VPN/Proxy/Tor and fraud scoring"
    requires_key = True

    def initialize(self, config) -> None:
        self._key = os.environ.get("IPQS_API_KEY", "")
        self._timeout = getattr(config, "api_timeout", 5) if config else 5
        self._session = build_session(self._timeout)

    def is_available(self) -> bool:
        return bool(self._key)

    def search(self, ip: str) -> dict:
        try:
            validate_ip(ip)
        except ValidationError:
            return {}
        try:
            resp = self._session.get(
                IPQS_URL.format(key=self._key, ip=ip),
                params={"strictness": 1, "allow_public_access_points": "true"},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return {"ipqs_fraud_score": None}
            d = resp.json()
            return {
                "ipqs_fraud_score": d.get("fraud_score"),
                "ipqs_vpn": d.get("vpn"),
                "ipqs_proxy": d.get("proxy"),
                "ipqs_tor": d.get("tor"),
                "ipqs_active_vpn": d.get("active_vpn"),
                "ipqs_isp": d.get("ISP"),
                "ipqs_asn": d.get("ASN"),
                "ipqs_connection": d.get("connection_type"),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("IPQualityScore lookup failed: %s", exc)
            return {}
