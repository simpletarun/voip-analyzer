"""PDF report exporter (requires reportlab)."""

import logging

from src.export.base import Exporter
from src.models.session import SessionReport

logger = logging.getLogger(__name__)

HAS_REPORTLAB = False
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table
    HAS_REPORTLAB = True
except ImportError:
    pass


class PdfExporter(Exporter):
    def export(self, report: SessionReport, peers: dict[str, dict], path: str) -> bool:
        if not HAS_REPORTLAB:
            logger.error("reportlab not installed - cannot export PDF")
            return False
        try:
            doc = SimpleDocTemplate(path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = [
                Paragraph("VoIP Analysis Report", styles["Title"]),
                Spacer(1, 12),
                Paragraph(
                    f"Timestamp: {report.timestamp}<br/>"
                    f"Duration: {report.duration_seconds:.1f}s<br/>"
                    f"Packets: {report.total_packets} | Bytes: {report.total_bytes}<br/>"
                    f"P2P: {report.p2p_count} | Relay: {report.relay_count}<br/>"
                    f"Countries: {', '.join(report.countries) or 'N/A'}",
                    styles["Normal"],
                ),
                Spacer(1, 12),
            ]
            data = [["IP", "Type", "ISP", "City", "Country", "ASN", "Pkts", "Bytes"]]
            for ip, d in peers.items():
                intel = d.get("intel")
                stats = d.get("stats", {})
                data.append([
                    ip, d.get("type", "UNKNOWN"),
                    intel.isp if intel else "Unknown",
                    intel.city if intel else "Unknown",
                    intel.country if intel else "Unknown",
                    intel.asn if intel else "N/A",
                    str(stats.get("packets", 0)),
                    str(stats.get("bytes", 0)),
                ])
            table = Table(data, repeatRows=1)
            table.setStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#001a00")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.green),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.green),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ])
            story.append(table)
            doc.build(story)
            logger.info("PDF exported: %s", path)
            return True
        except OSError as exc:
            logger.error("PDF export failed: %s", exc)
            return False
