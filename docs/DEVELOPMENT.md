# Development Guide

## Prerequisites
* Python 3.10+
* Npcap (Windows packet capture) — `npcap-installer.exe` is bundled

## Setup
```bash
git clone <repo>
cd voip-analyzer
python -m venv .venv && .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running
```bash
python -m src.main          # or: voip-analyzer
```
Run as Administrator/root for live capture.

## Environment configuration
Copy `.env.example` to `.env` and override any setting:

| Variable | Effect |
|----------|--------|
| `VOIP_DEBUG` | enable debug logging |
| `VOIP_API_TIMEOUT` | per-request timeout (s) |
| `VOIP_CACHE_TTL` | IP cache TTL (hours) |
| `VOIP_MAX_API_CALLS` | API calls per minute (rate limit) |
| `VOIP_DB_PATH` | SQLite path |
| `VOIP_LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR |
| `VOIP_THEME` | dark/light |
| `VOIP_INTERFACE` | capture interface |

Enrichment keys (optional): `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
`SHODAN_API_KEY`, `IPQS_API_KEY`, `NUMVERIFY_API_KEY`.

## Quality gates
```bash
ruff check src/ tests/        # lint
ruff format src/ tests/       # format
mypy src/                     # types
pytest -q                     # tests (+ coverage)
```

## Building a standalone executable
```bash
pip install pyinstaller
pyinstaller cutter.spec --noconfirm
iscc installer.iss            # Windows installer (Inno Setup)
```

## Project layout
```
src/
  app.py / main.py   entry point, logging, disclaimer
  config.py          AppConfig
  models/            PacketInfo, IPInfo, SessionReport
  database/          SQLite connection + repositories
  export/            CSV/JSON/HTML/Markdown/Excel/PDF exporters
  plugins/           VoIP protocol classifiers
  enrichment/        third-party IP intel plugins
  services/          capturer, ip_intel, network_analyzer
  ui/                PyQt6 GUI
  utils/             validation, errors, concurrency
tests/               pytest suite
docs/                architecture, plugins, database, development
```
