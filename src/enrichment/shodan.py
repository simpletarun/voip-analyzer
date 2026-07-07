"""Shodan enrichment.

Requires ``SHODAN_API_KEY``. Returns open ports, organization, ISP and a
hosting flag derived from Shodan's host data.
"""

import logging
import os

import requests

from src.enrichment.base import EnrichmentPlugin
from src.utils.errors import ValidationError
from src.utils.validation import validate_ip

logger = logging.getLogger(__name__)

SH_URL = "https://api.shodan.io/shodan/host/{ip}"


class ShodanPlugin(EnrichmentPlugin):
    name = "shodan"
    version = "1.0.0"
    description = "Shodan open ports, services and organization"
    requires_key = True

    def initialize(self, config) -> None:
        self._key = os.environ.get("SHODAN_API_KEY", "")
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
                SH_URL.format(ip=ip),
                params={"key": self._key},
                timeout=self._timeout,
                verify=True,
            )
            if resp.status_code != 200:
                return {"shodan_ports": []}
            data = resp.json()
            ports = data.get("ports", [])
            return {
                "shodan_ports": ports,
                "shodan_org": data.get("org"),
                "shodan_isp": data.get("isp"),
                "shodan_os": data.get("os"),
                "shodan_hosting": bool(data.get("hostnames")),
                "shodan_services": [
                    f"{m.get('port')}/{m.get('transport')}" for m in data.get("data", [])
                ],
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Shodan lookup failed: %s", exc)
            return {}
