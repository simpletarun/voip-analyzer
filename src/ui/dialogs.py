import logging
import webbrowser

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from src.models.ip_info import IPInfo
from src.plugins.whatsapp import WhatsAppPlugin

logger = logging.getLogger(__name__)


class IPDetailDialog(QDialog):
    def __init__(self, parent, ip: str, intel: IPInfo, stats: dict, ip_type: str):
        super().__init__(parent)
        self.setWindowTitle(f"IP Detail: {ip}")
        self.setMinimumSize(550, 500)
        self.resize(600, 550)

        layout = QVBoxLayout(self)

        title = QLabel(f"{'P2P PEER' if ip_type == 'P2P_PEER' else 'RELAY SERVER'}: {ip}")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #0f0; padding: 8px;")
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form = QVBoxLayout(content)

        peer_score = WhatsAppPlugin.peer_confidence(intel, stats) if ip_type == "P2P_PEER" else 0
        sections = [
            ("IP Address", ip),
            ("Version", "IPv6" if intel.is_ipv6 else "IPv4"),
            ("Classification", f"{ip_type} (confidence: {intel.confidence:.0%})"),
            ("Score", str(intel.score)),
        ]
        if ip_type == "P2P_PEER":
            label = f"Real Peer Confidence: {peer_score}%"
            color = "#0f0" if peer_score >= 60 else "#fa0"
            sections.append(("Real Peer",
                            f'<span style="color:{color};font-weight:bold">{peer_score}%</span>'))
        sections += [
            ("", ""),
            ("ISP", intel.isp),
            ("Organization", intel.org),
            ("ASN", intel.asn),
            ("Reverse DNS", intel.reverse_dns or "N/A"),
            ("", ""),
            ("City", intel.city),
            ("Country", intel.country),
            ("Latitude", f"{intel.lat:.4f}"),
            ("Longitude", f"{intel.lon:.4f}"),
            ("", ""),
            ("Mobile", str(intel.is_mobile)),
            ("Proxy/VPN", str(intel.is_proxy)),
            ("Hosting/DC", str(intel.is_hosting)),
            ("", ""),
            ("Packets", str(stats.get("packets", 0))),
            ("Bytes", f"{stats.get('bytes', 0):,}"),
            ("Inbound", str(stats.get("inbound", 0))),
            ("Outbound", str(stats.get("outbound", 0))),
        ]

        form_l = QFormLayout()
        for label, value in sections:
            if not label:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                sep.setStyleSheet("color: #0f0;")
                form_l.addRow(sep)
            else:
                lbl = QLabel(f"<b>{label}:</b>")
                val = QLabel(str(value))
                val.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse)
                form_l.addRow(lbl, val)

        form.addLayout(form_l)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy IP")
        copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(ip))
        btn_row.addWidget(copy_btn)

        if intel.lat and intel.lon:
            map_btn = QPushButton("Open in Maps")
            map_btn.clicked.connect(
                lambda: self._open_map(intel.lat, intel.lon))
            btn_row.addWidget(map_btn)

        form.addLayout(btn_row)
        scroll.setWidget(content)
        layout.addWidget(scroll)

        close_btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_btn.rejected.connect(self.accept)
        layout.addWidget(close_btn)

    def _open_map(self, lat: float, lon: float) -> None:
        webbrowser.open(f"https://www.google.com/maps?q={lat},{lon}")
