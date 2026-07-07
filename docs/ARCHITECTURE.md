# Architecture

Cutter (VoIP Analyzer) is a PyQt6 desktop application for authorized, local
network forensics of VoIP traffic (WhatsApp, Signal, Telegram, Google Meet).

## High-level flow

```mermaid
flowchart TD
    A[main.py] --> B[app.py: run()]
    B --> C[VoIPAnalyzerGUI]
    C --> D[PacketCapturer]
    D -->|scapy sniff| E[NetworkAnalyzer]
    D -->|classify| F[PluginManager: VoIP plugins]
    D -->|resolve IP| G[IPIntelligence]
    G -->|ip-api.com| H[(SQLite cache)]
    G -->|optional keys| I[EnrichmentManager]
    I --> J[VirusTotal / AbuseIPDB / Shodan / IPQS]
    G --> H
    C --> M[Exporters: CSV/JSON/HTML/MD/XLSX/PDF]
    C --> N[(SQLite: sessions, peers, cache)]
```

## Layer responsibilities

| Layer | Package | Responsibility |
|-------|---------|----------------|
| Entry | `src/main.py`, `src/app.py` | bootstrap, logging, disclaimer |
| Config | `src/config.py` | `AppConfig` dataclass, JSON + `.env` |
| Models | `src/models/` | `PacketInfo`, `IPInfo`, `SessionReport` |
| Data | `src/database/` | SQLite connection, migrations, repositories |
| Services | `src/services/` | capture, IP intel, network detection |
| Plugins | `src/plugins/` | VoIP protocol classifiers |
| Enrichment | `src/enrichment/` | third-party IP intelligence plugins |
| Export | `src/export/` | report exporters |
| UI | `src/ui/` | PyQt6 GUI, dialogs, theme |
| Utils | `src/utils/` | validation, errors, concurrency |

## Concurrency model

* `PacketCapturer` runs scapy in a dedicated thread and pushes packets onto a
  `queue.Queue`. A dispatcher thread emits UI events that are flushed on the
  Qt timer.
* `IPIntelligence` uses a `WorkerPool` (`ThreadPoolExecutor`) so IP enrichment
  lookups (ip-api + enrichment plugins) run concurrently instead of serially.
* API rate limiting is enforced per minute (`max_api_calls_per_min`).
