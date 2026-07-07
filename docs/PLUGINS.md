# Plugin Development Guide

Cutter supports two independent plugin systems.

## 1. VoIP protocol classifiers (`src/plugins/`)

Used to identify and classify captured packets (e.g. WhatsApp, Signal).

Implement `src.plugins.base.ProtocolPlugin`:

```python
from typing import Any, Dict
from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin


class MyVoIPPlugin(ProtocolPlugin):
    name = "MyVoIP"

    def identify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        # Return P2P_PEER, RELAY, USER or UNKNOWN
        return "UNKNOWN"

    def describe(self, pkt: Any) -> str:
        # Return a human-readable protocol name or "Unknown"
        return "Unknown"
```

Drop the module into `src/plugins/`; `PluginManager` discovers it
automatically via `pkgutil`.

## 2. IP enrichment plugins (`src/enrichment/`)

Augment geolocation with third-party intelligence (abuse scores, VPN/Tor
detection, open ports, etc.).

Implement `src.enrichment.base.EnrichmentPlugin`:

```python
import os
from typing import Any, Dict
from src.enrichment.base import EnrichmentPlugin


class ExamplePlugin(EnrichmentPlugin):
    name = "example"
    version = "1.0.0"
    description = "Demonstrates the enrichment interface"
    requires_key = True

    def initialize(self, config: Any) -> None:
        self._key = os.environ.get("EXAMPLE_API_KEY", "")
        self._timeout = getattr(config, "api_timeout", 5) if config else 5

    def is_available(self) -> bool:
        return bool(self._key)

    def search(self, ip: str) -> Dict[str, Any]:
        # Never raise; return a flat dict of fields or {} on failure.
        return {"example_score": 0}

    def metadata(self) -> Dict[str, Any]:
        return super().metadata()
```

`EnrichmentManager` discovers plugins in `src/enrichment/`, initializes them,
skips any whose `is_available()` is `False`, and runs all `search()` calls
concurrently via `WorkerPool`.

### Available enrichment plugins

| Plugin | Env var | Provides |
|--------|---------|----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | malicious/suspicious vote counts |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | abuse confidence + report count |
| Shodan | `SHODAN_API_KEY` | open ports, org, ISP, OS |
| IPQualityScore | `IPQS_API_KEY` | VPN/Proxy/Tor + fraud score |

## Secrets

Never commit API keys. All plugins read keys from the environment
(`python-dotenv` loads `.env`). See `.env.example`.
