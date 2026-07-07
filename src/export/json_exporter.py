import json
import logging
from dataclasses import asdict

from src.export.base import Exporter
from src.models.session import SessionReport

logger = logging.getLogger(__name__)


class JsonExporter(Exporter):
    def export(self, report: SessionReport, peers: dict[str, dict], path: str) -> bool:
        try:
            data = {
                "report": asdict(report),
                "peers": {
                    ip: {
                        "type": d.get("type"),
                        "intel": d["intel"].to_dict() if d.get("intel") else None,
                        "stats": d.get("stats", {})
                    } for ip, d in peers.items()
                }
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("JSON exported: %s", path)
            return True
        except OSError as e:
            logger.error("JSON export failed: %s", e)
            return False
