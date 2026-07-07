"""VirusTotal IP enrichment.

Requires ``VIRUSTOTAL_API_KEY`` in the environment. Returns abuse/confidence
signals derived from VirusTotal's IP report.
"""

import logging
import os

from src.enrichment.base import EnrichmentPlugin
from src.utils.errors import ValidationError
from src.utils.http import build_session
from src.utils.validation import validate_ip

logger = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalPlugin(EnrichmentPlugin):
    name = "virustotal"
    version = "1.0.0"
    description = "VirusTotal IP reputation (malicious vote count)"
    requires_key = True

    def initialize(self, config) -> None:
        self._key = os.environ.get("VIRUSTOTAL_API_KEY", "")
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
                VT_URL.format(ip=ip),
                headers={"x-apikey": self._key},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return {"vt_malicious": None}
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "vt_reputation": attrs.get("reputation"),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("VirusTotal lookup failed: %s", exc)
            return {}
