"""Base interface for IP enrichment plugins.

Enrichment plugins augment the core geolocation data with third-party
intelligence (abuse scores, blacklists, VPN/Tor detection, open ports, etc.).
Every plugin exposes a uniform interface so the manager can load, initialize
and query them uniformly and concurrently.

A plugin that needs a secret MUST read it from the environment (never hard-code
or commit keys). If the required key is absent the plugin simply reports
``is_available() == False`` and is skipped.
"""

from typing import Any


class EnrichmentPlugin:
    name: str = "base"
    version: str = "1.0.0"
    description: str = ""
    requires_key: bool = False

    def initialize(self, config: Any) -> None:
        """Prepare the plugin. Override to read env vars / configure clients."""

    def is_available(self) -> bool:
        """Return True if the plugin can run (e.g. required key present)."""
        return True

    def search(self, ip: str) -> dict[str, Any]:
        """Return a flat dict of enrichment fields for ``ip``.

        Implementations must never raise; on failure return an empty dict and
        let the manager handle logging.
        """
        return {}

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "requires_key": self.requires_key,
            "available": self.is_available(),
        }
