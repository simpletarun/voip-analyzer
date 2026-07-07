import csv
import logging

from src.export.base import Exporter
from src.models.session import SessionReport

logger = logging.getLogger(__name__)


class CsvExporter(Exporter):
    def export(self, report: SessionReport, peers: dict[str, dict], path: str) -> bool:
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Session Report"])
                w.writerow(["Timestamp", report.timestamp])
                w.writerow(["Duration (s)", f"{report.duration_seconds:.1f}"])
                w.writerow(["Total Packets", report.total_packets])
                w.writerow(["Total Bytes", report.total_bytes])
                w.writerow(["P2P Peers", report.p2p_count])
                w.writerow(["Relay Servers", report.relay_count])
                w.writerow([])
                w.writerow(["IP", "Type", "ISP", "City", "Country",
                            "ASN", "Packets", "Bytes", "Confidence"])
                for ip, data in peers.items():
                    intel = data.get("intel")
                    stats = data.get("stats", {})
                    w.writerow([
                        ip, data.get("type", "UNKNOWN"),
                        intel.isp if intel else "Unknown",
                        intel.city if intel else "Unknown",
                        intel.country if intel else "Unknown",
                        intel.asn if intel else "N/A",
                        stats.get("packets", 0),
                        stats.get("bytes", 0),
                        f"{intel.confidence:.2f}" if intel else "0.00"
                    ])
            logger.info("CSV exported: %s", path)
            return True
        except OSError as e:
            logger.error("CSV export failed: %s", e)
            return False
