"""AbuseIPDB enrichment.

Requires ``ABUSEIPDB_API_KEY``. Returns the abuse score (0-100) and total
reports for an IP.
"""

import logging
import os

import requests

from src.enrichment.base import EnrichmentPlugin
from src.utils.errors import ValidationError
from src.utils.validation import validate_ip

logger = logging.getLogger(__name__)

AB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBPlugin(EnrichmentPlugin):
    name = "abuseipdb"
    version = "1.0.0"
    description = "AbuseIPDB abuse confidence score and report count"
    requires_key = True

    def initialize(self, config) -> None:
        self._key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self._timeout = getattr(config, "api_timeout", 5) if config else 5

    def is_available(self) -> bool:
        return bool(self._key)

    def search(self, ip: str) -> dict:
        try:
            validate_ip(ip)
        except ValidationError:
            return {}
        try:
            resp = requests.get(
                AB_URL,
                headers={"Key": self._key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self._timeout,
                verify=True,
            )
            if resp.status_code != 200:
                return {"abuse_score": None}
            data = resp.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore"),
                "abuse_reports": data.get("totalReports", 0),
                "abuse_isp": data.get("isp"),
                "abuse_usage": data.get("usageType"),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("AbuseIPDB lookup failed: %s", exc)
            return {}
