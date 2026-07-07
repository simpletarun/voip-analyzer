import concurrent.futures
import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional, Pattern

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QColor, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMenuBar, QMessageBox, QPlainTextEdit,
    QPushButton, QSplitter, QTabWidget, QTableWidget, QTextBrowser,
    QTableWidgetItem, QVBoxLayout, QWidget,
)
from PyQt6.QtGui import QDesktopServices

from src import __version__
from src.config import AppConfig
from src.database.connection import DatabaseConnection
from src.database.repository import CacheRepository, PeerRepository, SessionRepository
from src.export.html_exporter import HtmlExporter
from src.export.csv_exporter import CsvExporter
from src.export.json_exporter import JsonExporter
from src.models.ip_info import IPInfo
from src.models.packet import PacketInfo
from src.models.session import SessionReport
from src.plugins.whatsapp import WhatsAppPlugin
from src.services.capturer import PacketCapturer
from src.services.ip_intel import IPIntelligence
from src.ui.dialogs import IPDetailDialog
from src.ui.theme import ThemeEngine

logger = logging.getLogger(__name__)

HAS_FOLIUM = False
try:
    import folium
    HAS_FOLIUM = True
except ImportError:
    pass

HAS_WEBENGINE = False
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    HAS_WEBENGINE = True
except ImportError:
    pass

HAS_WHOIS = False
try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    pass

HAS_SCAPY = False
try:
    from scapy.all import conf
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


_RE_THREAD = concurrent.futures.ThreadPoolExecutor(max_workers=1)

def _safe_compile_regex(pattern: str, timeout: float = 0.5) -> Optional[Pattern]:
    try:
        future = _RE_THREAD.submit(lambda: re.compile(pattern, re.IGNORECASE))
        return future.result(timeout=timeout)
    except Exception:
        return None


class VoIPAnalyzerGUI(QMainWindow):
    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config
        self.db = DatabaseConnection(config.db_path)
        self.session_repo = SessionRepository(self.db)
        self.peer_repo = PeerRepository(self.db)
        self.cache_repo = CacheRepository(self.db)
        self.capturer: Optional[PacketCapturer] = None
        self.all_data: Dict[str, Dict] = {}
        self.countries: set = set()
        self._uptime_start: Optional[float] = None
        self._last_primary_ip: str = ""
        self._pkt_buffer: list = []
        self._buf_lock = threading.Lock()
        self._filter_state: tuple = ("", "All", "All")

        self._ui_event_queue: list = []
        self._ui_event_lock = threading.Lock()

        self._gui_timer = QTimer()
        self._gui_timer.timeout.connect(self._flush_gui)
        self._gui_timer.start(config.gui_update_interval_ms)

        self._stats_timer = QTimer()
        self._stats_timer.timeout.connect(self._update_stats_display)
        self._stats_timer.start(config.stats_update_interval_ms)

        self._cleanup_timer = QTimer()
        self._cleanup_timer.timeout.connect(self._cleanup_cache)
        self._cleanup_timer.start(3600 * 1000)

        self._map_timer = QTimer()
        self._map_timer.timeout.connect(self._refresh_map)
        self._map_timer.start(3000)

        self._retention_cleanup()

        self._build_ui()

    def _build_ui(self) -> None:
        self.setWindowTitle(f"VoIP Analyzer v{__version__}")
        self.resize(1700, 950)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)

        left = QWidget()
        ll = QVBoxLayout(left)

        hdr = QLabel("VoIP Analyzer")
        hdr.setStyleSheet("font-size: 22px; font-weight: bold; color: #0f0;")
        ll.addWidget(hdr)

        self.ip_label = QLabel("Detecting your IP...")
        self.ip_label.setStyleSheet(
            "color: #0ff; padding: 8px; background: #001a1a; border: 1px solid #0ff;")
        ll.addWidget(self.ip_label)

        ctrl = QHBoxLayout()
        self.start_btn = QPushButton("START (F5)")
        self.start_btn.clicked.connect(self.start_capture)
        ctrl.addWidget(self.start_btn)

        self.stop_btn = QPushButton("STOP (F6)")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("CLEAR")
        self.clear_btn.clicked.connect(self.clear_data)
        ctrl.addWidget(self.clear_btn)
        ll.addLayout(ctrl)

        st = QHBoxLayout()
        self.status_lbl = QLabel("READY")
        self.status_lbl.setStyleSheet("color: #ff0; font-weight: bold;")
        st.addWidget(self.status_lbl)
        self.mode_lbl = QLabel("MODE: UNKNOWN")
        self.mode_lbl.setStyleSheet("color: #f0f; font-weight: bold;")
        st.addWidget(self.mode_lbl)
        self.pkt_lbl = QLabel("PKT: 0")
        self.pkt_lbl.setStyleSheet("color: #0ff; font-weight: bold;")
        st.addWidget(self.pkt_lbl)
        ll.addLayout(st)

        stats_frame = QFrame()
        stats_frame.setObjectName("stats_frame")
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(10, 5, 10, 5)

        self.pps_lbl = QLabel("PPS: 0")
        stats_layout.addWidget(self.pps_lbl)
        self.bps_lbl = QLabel("BPS: 0 KB/s")
        stats_layout.addWidget(self.bps_lbl)
        self.unique_ips_lbl = QLabel("IPs: 0")
        stats_layout.addWidget(self.unique_ips_lbl)
        self.uptime_lbl = QLabel("Uptime: 00:00:00")
        stats_layout.addWidget(self.uptime_lbl)
        self.total_bytes_lbl = QLabel("Total: 0 KB")
        stats_layout.addWidget(self.total_bytes_lbl)
        ll.addWidget(stats_frame)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Regex: filter by IP, ISP, City...")
        self.search_box.textChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.search_box, 1)

        filter_row.addWidget(QLabel("Type:"))
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All", "P2P_PEER", "RELAY", "UNKNOWN"])
        self.type_filter.currentTextChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.type_filter)

        filter_row.addWidget(QLabel("Protocol:"))
        self.proto_filter = QComboBox()
        self.proto_filter.addItems(["All", "UDP", "TCP"])
        self.proto_filter.currentTextChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.proto_filter)
        ll.addLayout(filter_row)

        self.table = QTableWidget()
        self.table.setColumnCount(12)
        self.table.setHorizontalHeaderLabels([
            "#", "TIME", "DIR", "SRC", "DST", "PROTO", "VER",
            "TYPE", "PROTOCOL", "ISP", "CITY", "COUNTRY"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        ll.addWidget(self.table)

        self.console = QPlainTextEdit()
        self.console.setMaximumHeight(120)
        self.console.setReadOnly(True)
        ll.addWidget(self.console)

        right = QWidget()
        rl = QVBoxLayout(right)
        self.tabs = QTabWidget()

        pw = QWidget()
        pl = QVBoxLayout(pw)
        self.p2p_header = QLabel("P2P PEERS")
        pl.addWidget(self.p2p_header)
        p2p_btn_row = QHBoxLayout()
        self.whois_btn = QPushButton("WHOIS Selected IP")
        self.whois_btn.clicked.connect(self._whois_selected_ip)
        self.whois_btn.setEnabled(HAS_WHOIS)
        p2p_btn_row.addWidget(self.whois_btn)
        p2p_btn_row.addStretch()
        pl.addLayout(p2p_btn_row)
        self.p2p_table = QTableWidget()
        self.p2p_table.setColumnCount(11)
        self.p2p_table.setHorizontalHeaderLabels([
            "IP", "VER", "PKTS", "BYTES", "IN", "OUT", "SCORE",
            "ISP", "CITY", "COUNTRY", "ASN"
        ])
        self.p2p_table.horizontalHeader().setStretchLastSection(True)
        self.p2p_table.cellClicked.connect(
            lambda r, c: self._show_ip_detail(self.p2p_table, r))
        pl.addWidget(self.p2p_table)
        self.tabs.addTab(pw, "P2P PEERS")

        rw = QWidget()
        rrl = QVBoxLayout(rw)
        rb = QLabel("RELAY SERVERS")
        rrl.addWidget(rb)
        self.relay_table = QTableWidget()
        self.relay_table.setColumnCount(10)
        self.relay_table.setHorizontalHeaderLabels([
            "IP", "VER", "PKTS", "BYTES", "IN", "OUT", "ISP", "CITY", "COUNTRY", "ASN"
        ])
        self.relay_table.horizontalHeader().setStretchLastSection(True)
        self.relay_table.cellClicked.connect(
            lambda r, c: self._show_ip_detail(self.relay_table, r))
        rrl.addWidget(self.relay_table)
        self.tabs.addTab(rw, "RELAYS")

        hw = QWidget()
        hl = QVBoxLayout(hw)
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            "ID", "DATE", "DURATION", "PACKETS", "BYTES", "P2P", "RELAY", "COUNTRIES"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        hl.addWidget(self.history_table)
        refresh_btn = QPushButton("Refresh History")
        refresh_btn.clicked.connect(self._load_session_history)
        hl.addWidget(refresh_btn)
        self.tabs.addTab(hw, "HISTORY")

        mw = QWidget()
        ml = QVBoxLayout(mw)
        if HAS_WEBENGINE and HAS_FOLIUM:
            self.web_view = QWebEngineView()
            ml.addWidget(self.web_view)
            self._map_html = ""
        else:
            map_btn_row = QHBoxLayout()
            self.open_map_btn = QPushButton("Open Interactive Map in Browser")
            self.open_map_btn.clicked.connect(self._open_map_in_browser)
            self.open_map_btn.setStyleSheet("font-size: 14px; padding: 10px;")
            map_btn_row.addWidget(self.open_map_btn)
            ml.addLayout(map_btn_row)
            self.map_location_table = QTableWidget()
            self.map_location_table.setColumnCount(7)
            self.map_location_table.setHorizontalHeaderLabels([
                "IP", "TYPE", "ISP", "CITY", "COUNTRY", "LAT", "LON"
            ])
            self.map_location_table.horizontalHeader().setStretchLastSection(True)
            ml.addWidget(self.map_location_table)
        self.tabs.addTab(mw, "MAP")

        rl.addWidget(self.tabs)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([400, 700])
        root.addWidget(splitter)

        self._build_menu()
        self.statusBar().showMessage(
            f"v{__version__} | DB: {self.config.db_path} | "
            f"Cache TTL: {self.config.cache_ttl_hours}h")

        self._log("Analyzer initialized.")
        self._log(f"Version: {__version__}")
        if not HAS_SCAPY:
            self._log("WARNING: Scapy not installed - capture disabled")
        self._log("Run as Administrator for packet capture.")
        self._load_session_history()
        if HAS_FOLIUM:
            self._init_map()

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        export_action = QAction("&Export Report...", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        view_menu = menubar.addMenu("&View")
        theme_menu = view_menu.addMenu("&Theme")
        for theme_name in ThemeEngine.THEMES:
            action = QAction(theme_name.capitalize(), self)
            action.triggered.connect(lambda checked, t=theme_name: self._apply_theme(t))
            theme_menu.addAction(action)

        cleanup_action = QAction("Cleanup &Cache", self)
        cleanup_action.triggered.connect(self._cleanup_cache)
        view_menu.addAction(cleanup_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        shortcuts_action = QAction("&Keyboard Shortcuts", self)
        shortcuts_action.triggered.connect(self._show_shortcuts)
        help_menu.addAction(shortcuts_action)

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{ts}] {msg}")
        logger.info(msg)

    def start_capture(self) -> None:
        if self.capturer and self.capturer.running:
            return
        if not HAS_SCAPY:
            QMessageBox.critical(self, "Error",
                                 "Scapy is not installed.\n\npip install scapy")
            return

        intel_service = IPIntelligence(self.cache_repo, self.config)
        self.capturer = PacketCapturer(self.config, self.session_repo, self.peer_repo,
                                       intel_service)

        self.capturer.on("packet", self._on_packet)
        self.capturer.on("new_peer", lambda *a: self._enqueue_ui_event("_on_new_peer", *a))
        self.capturer.on("peer_update", lambda *a: self._enqueue_ui_event("_on_peer_update", *a))
        self.capturer.on("status", lambda *a: self._enqueue_ui_event("_on_status", *a))
        self.capturer.on("log", lambda *a: self._enqueue_ui_event("_log", *a))
        self.capturer.on("error", lambda *a: self._enqueue_ui_event("_on_error", *a))

        ana = self.capturer.analyzer
        v6_str = f" | IPv6: {ana.my_public_ip_v6}" if ana.my_public_ip_v6 else ""
        self.ip_label.setText(
            f"IPv4: {ana.my_public_ip}{v6_str} | "
            f"Location: {ana.my_lat:.2f}, {ana.my_lon:.2f}")

        self._capture_thread = threading.Thread(
            target=self.capturer.run, daemon=True, name="Capture")
        self._capture_thread.start()
        self._uptime_start = time.time()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("CAPTURING")
        self.status_lbl.setStyleSheet("color: #0f0; font-weight: bold;")
        self._log("Capture started. Make a call.")
        self._log("Your IP is filtered out.")

    def stop_capture(self) -> None:
        if not self.capturer:
            return
        self.capturer.stop()

        report = self.capturer.get_report()
        session_id = self.session_repo.save(report)

        top_ip, top_score, top_isp = "N/A", 0, ""
        for ip, d in self.all_data.items():
            s = d.get("score", 0)
            if s > top_score:
                top_ip = ip
                top_score = s
                intel = d.get("intel")
                top_isp = f" | {intel.isp}" if intel and intel.isp not in ("Unknown", "") else ""

        self._log("=" * 58)
        self._log("SESSION REPORT")
        self._log(f"Session ID: {session_id}")
        self._log(f"Duration: {report.duration_seconds:.1f}s")
        self._log(f"Packets: {report.total_packets}")
        self._log(f"Bytes: {report.total_bytes:,}")
        self._log(f"P2P: {report.p2p_count} | Relay: {report.relay_count}")
        self._log(f"Call IP: {top_ip}{top_isp} (confidence: {top_score}%)")
        self._log(f"Countries: {', '.join(report.countries) or 'N/A'}")
        self._log("=" * 58)

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("STOPPED")
        self.status_lbl.setStyleSheet("color: #f00; font-weight: bold;")
        self._uptime_start = None
        self.capturer = None
        self._load_session_history()

    def _on_packet(self, pkt_info: PacketInfo) -> None:
        with self._buf_lock:
            self._pkt_buffer.append(pkt_info)
            if len(self._pkt_buffer) > self.config.max_table_rows:
                self._pkt_buffer = self._pkt_buffer[-self.config.max_table_rows // 2:]

    def _enqueue_ui_event(self, method_name: str, *args) -> None:
        with self._ui_event_lock:
            self._ui_event_queue.append((method_name, args))

    def _flush_ui_events(self) -> None:
        with self._ui_event_lock:
            if not self._ui_event_queue:
                return
            batch = list(self._ui_event_queue)
            self._ui_event_queue.clear()
        for method_name, args in batch:
            try:
                getattr(self, method_name)(*args)
            except Exception as e:
                logger.error("UI event error in %s: %s", method_name, e)

    def _flush_gui(self) -> None:
        self._flush_ui_events()

        batch = []
        with self._buf_lock:
            if not self._pkt_buffer:
                return
            batch = list(self._pkt_buffer)
            self._pkt_buffer.clear()

        self.table.setUpdatesEnabled(False)
        try:
            for pkt in batch:
                row = self.table.rowCount()
                if row >= self.config.max_table_rows:
                    self.table.removeRow(0)
                    row = self.table.rowCount()
                self.table.insertRow(row)

                arrow = "\u2192" if pkt.direction == "outbound" else "\u2190"
                stun = " STUN" if pkt.is_stun else ""
                ver_str = f"v{pkt.ver}"
                vals = [
                    str(pkt.id), pkt.time, arrow,
                    pkt.src, pkt.dst, pkt.proto, ver_str,
                    f"{pkt.ip_type}{stun}",
                    pkt.protocol_name,
                    pkt.isp, pkt.city, pkt.country
                ]
                for col, val in enumerate(vals):
                    item = QTableWidgetItem(str(val))
                    if pkt.ip_type == "P2P_PEER":
                        item.setForeground(QColor("#0f0"))
                    elif pkt.ip_type == "RELAY":
                        item.setForeground(QColor("#fa0"))
                    self.table.setItem(row, col, item)
        finally:
            self.table.setUpdatesEnabled(True)

        self.table.scrollToBottom()
        self.pkt_lbl.setText(f"PKT: {batch[-1].id}")
        self._apply_filter()

    def _on_new_peer(self, ip: str, intel: IPInfo, stats: Dict, ip_type: str) -> None:
        self.all_data[ip] = {"intel": intel, "stats": stats, "type": ip_type, "score": 0}
        self._log(f"NEW IP: {ip} (resolving...)")

    def _on_peer_update(self, ip: str, intel: IPInfo, stats: Dict, ip_type: str) -> None:
        old = self.all_data.get(ip, {})
        old_type = old.get("type", "UNKNOWN")
        score = WhatsAppPlugin.peer_confidence(intel, stats)

        if ip_type == "P2P_PEER":
            table = self.p2p_table
            color = QColor("#0f0")
            if old_type != "P2P_PEER":
                self._log(f"P2P PEER: {ip} | {intel.isp} (confidence: {score}%)")
                self.tabs.setCurrentIndex(0)
        elif ip_type == "RELAY":
            table = self.relay_table
            color = QColor("#fa0")
            if old_type != "RELAY":
                self._log(f"RELAY: {ip} | {intel.isp}")
        else:
            table = self.relay_table
            color = QColor("#888")

        row = self._find_ip_row(table, ip)
        if row < 0:
            row = table.rowCount()
            table.insertRow(row)

        is_p2p = (table is self.p2p_table)
        self._update_ip_row(table, row, ip, intel, stats, color, score)
        self.all_data[ip] = {"intel": intel, "stats": stats, "type": ip_type, "score": score}

        if is_p2p:
            self._sort_p2p_table()
            self._update_p2p_header()
            self._recolor_p2p_table()

        self._refresh_packet_table_ip(ip, intel)
        self._update_map_table()

        country = intel.country
        if country and country not in ("Unknown", "...") and country not in self.countries:
            self.countries.add(country)

    def _refresh_packet_table_ip(self, ip: str, intel: IPInfo) -> None:
        for row in range(self.table.rowCount()):
            src_item = self.table.item(row, 3)
            dst_item = self.table.item(row, 4)
            if not src_item or not dst_item:
                continue
            if src_item.text() == ip or dst_item.text() == ip:
                for col, val in [(9, intel.isp), (10, intel.city), (11, intel.country)]:
                    item = self.table.item(row, col)
                    if item:
                        item.setText(str(val))

    def _on_status(self, mode: str, p2p_count: int, relay_count: int) -> None:
        has_high_conf = any(
            d.get("score", 0) >= 60 for d in self.all_data.values()
        ) if self.all_data else False
        if mode == "P2P" and has_high_conf:
            self.mode_lbl.setText(f"MODE: \U0001f3af PRIMARY CALL ({p2p_count} peers)")
            self.mode_lbl.setStyleSheet("color: #00ffff; font-weight: bold;")
        elif mode == "P2P":
            self.mode_lbl.setText(f"MODE: P2P ({p2p_count} peers)")
            self.mode_lbl.setStyleSheet("color: #0f0; font-weight: bold;")
        elif mode == "RELAY":
            self.mode_lbl.setText(f"MODE: RELAY ({relay_count})")
            self.mode_lbl.setStyleSheet("color: #fa0; font-weight: bold;")
        elif mode == "MIXED":
            self.mode_lbl.setText(f"MODE: MIXED (P2P:{p2p_count} RELAY:{relay_count})")
            self.mode_lbl.setStyleSheet("color: #f0f; font-weight: bold;")
        else:
            self.mode_lbl.setText(f"MODE: {mode}")

    def _on_error(self, msg: str) -> None:
        self._log(f"ERROR: {msg}")
        QMessageBox.critical(self, "Error", msg)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    @staticmethod
    def _find_ip_row(table: QTableWidget, ip: str) -> int:
        for r in range(table.rowCount()):
            item = table.item(r, 0)
            if item and item.text() == ip:
                return r
        return -1

    @staticmethod
    def _update_ip_row(table: QTableWidget, row: int, ip: str,
                       intel: IPInfo, stats: Dict, color: QColor,
                       score: int = 0) -> None:
        ver_str = "v6" if intel.is_ipv6 else "v4"
        is_p2p = (table.columnCount() >= 11)
        vals = [
            ip, ver_str,
            str(stats.get("packets", 0)),
            f"{stats.get('bytes', 0):,}",
            str(stats.get("inbound", 0)),
            str(stats.get("outbound", 0)),
        ]
        if is_p2p:
            vals.append(str(score))
        vals += [intel.isp, intel.city, intel.country, intel.asn]
        for c, v in enumerate(vals):
            item = QTableWidgetItem(str(v))
            item.setForeground(color)
            table.setItem(row, c, item)

    def _sort_p2p_table(self) -> None:
        rows = []
        for r in range(self.p2p_table.rowCount()):
            ip_item = self.p2p_table.item(r, 0)
            score_item = self.p2p_table.item(r, 6)
            if ip_item and score_item:
                try:
                    rows.append((int(score_item.text()), ip_item.text(), r))
                except ValueError:
                    rows.append((0, "", r))
        rows.sort(key=lambda x: (-x[0], x[1]))
        new_data = []
        for _, _, old_row in rows:
            row_data = []
            for c in range(self.p2p_table.columnCount()):
                item = self.p2p_table.takeItem(old_row, c)
                row_data.append(item)
            new_data.append(row_data)
        self.p2p_table.setRowCount(0)
        for row_data in new_data:
            r = self.p2p_table.rowCount()
            self.p2p_table.insertRow(r)
            for c, item in enumerate(row_data):
                if item:
                    self.p2p_table.setItem(r, c, item)

    def _update_p2p_header(self) -> None:
        top_ip = "?"
        top_score = 0
        if self.p2p_table.rowCount() > 0:
            item = self.p2p_table.item(0, 0)
            score_item = self.p2p_table.item(0, 6)
            if item and score_item:
                top_ip = item.text()
                try:
                    top_score = int(score_item.text())
                except ValueError:
                    pass
        data = self.all_data.get(top_ip, {})
        intel = data.get("intel")
        isp = f" | {intel.isp}" if intel and intel.isp not in ("Unknown", "") else ""
        label = f"PEERS (top: {top_ip}{isp}, score: {top_score}%)"
        self.p2p_header.setText(label)

    def _recolor_p2p_table(self) -> None:
        for r in range(self.p2p_table.rowCount()):
            is_top = (r == 0)
            c = QColor("#00ffff") if is_top else QColor("#0f0")
            for col in range(self.p2p_table.columnCount()):
                item = self.p2p_table.item(r, col)
                if item:
                    item.setForeground(c)
        if self.p2p_table.rowCount() > 0:
            ip_item = self.p2p_table.item(0, 0)
            if ip_item:
                ip = ip_item.text()
                data = self.all_data.get(ip, {})
                intel = data.get("intel")
                score = data.get("score", 0)
                isp = intel.isp if intel else "?"
                if self._last_primary_ip != ip:
                    self._last_primary_ip = ip
                    self._log(f"CALL PARTICIPANT: {ip} | {isp} (confidence: {score}%)")

    def _on_filter_changed(self) -> None:
        new_state = (self.search_box.text(), self.type_filter.currentText(),
                     self.proto_filter.currentText())
        if new_state != self._filter_state:
            self._filter_state = new_state
            self._apply_filter()

    def _apply_filter(self) -> None:
        text = self.search_box.text().strip()
        type_text = self.type_filter.currentText()
        proto_text = self.proto_filter.currentText()

        use_regex = False
        compiled = None
        if text:
            if len(text) > 200:
                text = text[:200]
            compiled = _safe_compile_regex(text)
            if compiled is not None:
                use_regex = True

        for table in (self.table, self.p2p_table, self.relay_table):
            for row in range(table.rowCount()):
                if not text and type_text == "All" and proto_text == "All":
                    table.setRowHidden(row, False)
                    continue

                row_text = " ".join(
                    table.item(row, c).text().lower()
                    for c in range(table.columnCount())
                    if table.item(row, c))

                text_match = True
                if text:
                    if use_regex:
                        try:
                            text_match = bool(compiled.search(row_text))
                        except Exception:
                            text_match = False
                    else:
                        text_match = text.lower() in row_text

                type_match = True
                if type_text != "All":
                    found = False
                    for c in range(table.columnCount()):
                        item = table.item(row, c)
                        if item and type_text.upper() in item.text().upper():
                            found = True
                            break
                    type_match = found

                proto_match = True
                if proto_text != "All" and table == self.table:
                    item = table.item(row, 5)
                    if item:
                        proto_match = item.text() == proto_text

                table.setRowHidden(row, not (text_match and type_match and proto_match))

    def _show_ip_detail(self, table: QTableWidget, row: int) -> None:
        ip_item = table.item(row, 0)
        if not ip_item:
            return
        ip = ip_item.text()
        data = self.all_data.get(ip)
        if not data:
            return
        dlg = IPDetailDialog(self, ip, data["intel"], data["stats"], data["type"])
        dlg.exec()

    def _whois_selected_ip(self) -> None:
        rows = self.p2p_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "WHOIS",
                                    "Select a row in the P2P table first.")
            return
        ip = self.p2p_table.item(rows[0].row(), 0).text()
        self._perform_whois(ip)

    def _perform_whois(self, ip: str) -> None:
        if not HAS_WHOIS:
            QMessageBox.information(self, "WHOIS",
                                    "python-whois not installed.\npip install python-whois")
            return
        self._log(f"WHOIS lookup: {ip}...")
        try:
            w = python_whois.whois(ip)
            data = self.all_data.get(ip, {})
            intel = data.get("intel")
            info_lines = [
                f"<h2 style='color:#0f0'>WHOIS: {ip}</h2>",
                "<table style='color:#0f0;font-family:Consolas;font-size:13px;'>",
            ]
            fields = [
                ("IP", ip),
                ("ISP", intel.isp if intel else "N/A"),
                ("Org", str(w.org) if w.org else (intel.org if intel else "N/A")),
                ("Country", str(w.country) if w.country else (intel.country if intel else "N/A")),
                ("City", intel.city if intel else "N/A"),
                ("ASN", intel.asn if intel else "N/A"),
                ("Registrar", str(w.registrar) if w.registrar else "N/A"),
                ("Creation Date", str(w.creation_date) if w.creation_date else "N/A"),
                ("Expiration Date", str(w.expiration_date) if w.expiration_date else "N/A"),
                ("Name Servers", ", ".join(w.name_servers) if w.name_servers else "N/A"),
                ("Network", str(w.netrange) if hasattr(w, 'netrange') and w.netrange else "N/A"),
                ("CIDR", str(w.cidr) if hasattr(w, 'cidr') and w.cidr else "N/A"),
                ("Reverse DNS", intel.reverse_dns if intel and intel.reverse_dns else "N/A"),
            ]
            for label, val in fields:
                info_lines.append(
                    f"<tr><td style='padding:4px 12px;font-weight:bold;'>{label}</td>"
                    f"<td style='padding:4px 12px;'>{val}</td></tr>")
            info_lines.append("</table>")
            dlg = QMessageBox(self)
            dlg.setWindowTitle(f"WHOIS - {ip}")
            dlg.setTextFormat(Qt.TextFormat.RichText)
            dlg.setText("".join(info_lines))
            dlg.setMinimumWidth(600)
            dlg.exec()
            self._log(f"WHOIS complete: {ip}")
        except Exception as e:
            self._log(f"WHOIS failed: {ip} - {e}")
            QMessageBox.warning(self, "WHOIS Error",
                                f"WHOIS lookup failed for {ip}:\n{e}")

    def _update_stats_display(self) -> None:
        if self.capturer and self.capturer.running:
            total, pps, bps, p2p, relay, elapsed = self.capturer.get_live_stats()
            self.pps_lbl.setText(f"PPS: {pps:.0f}")
            self.bps_lbl.setText(f"BPS: {bps:.1f} KB/s")
            self.unique_ips_lbl.setText(f"IPs: {len(self.all_data)}")
            self.total_bytes_lbl.setText(f"Total: {total:,} pkts")
            if self._uptime_start:
                up = int(time.time() - self._uptime_start)
                hrs, rem = divmod(up, 3600)
                mins, secs = divmod(rem, 60)
                self.uptime_lbl.setText(f"Uptime: {hrs:02d}:{mins:02d}:{secs:02d}")
        else:
            self.pps_lbl.setText("PPS: 0")
            self.bps_lbl.setText("BPS: 0 KB/s")
            self.uptime_lbl.setText("Uptime: 00:00:00")

    def _load_session_history(self) -> None:
        sessions = self.session_repo.get_all()
        self.history_table.setRowCount(0)
        for s in sessions:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            ts = s.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
            except Exception:
                dt = ts[:16]
            duration = s.get("duration_seconds", 0)
            dur_str = f"{duration:.0f}s"
            countries = s.get("countries", "[]")
            try:
                countries = ", ".join(json.loads(countries)[:5])
            except Exception:
                countries = countries[:50]
            vals = [
                str(s.get("id", "")), dt, dur_str,
                str(s.get("total_packets", 0)),
                f"{s.get('total_bytes', 0):,}",
                str(s.get("p2p_count", 0)),
                str(s.get("relay_count", 0)),
                countries
            ]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                self.history_table.setItem(row, c, item)

    def _init_map(self) -> None:
        if HAS_WEBENGINE and HAS_FOLIUM:
            self._render_map()
        else:
            self._update_map_table()

    def _render_map(self) -> None:
        if not (HAS_WEBENGINE and HAS_FOLIUM):
            return
        try:
            lat = self.capturer.analyzer.my_lat if self.capturer else 20.0
            lon = self.capturer.analyzer.my_lon if self.capturer else 0.0
            my_ip = self.capturer.analyzer.my_public_ip if self.capturer else "N/A"
            m = folium.Map(location=[lat, lon], zoom_start=2,
                           tiles="CartoDB dark_matter")
            if self.capturer:
                folium.CircleMarker(
                    location=[lat, lon], radius=12,
                    popup=f"<b>YOU</b><br>{my_ip}",
                    color="cyan", fill=True, fill_color="cyan"
                ).add_to(m)
            for ip, data in self.all_data.items():
                intel = data.get("intel")
                if not intel or (intel.lat == 0 and intel.lon == 0):
                    continue
                c = "#0f0" if data.get("type") == "P2P_PEER" else "#fa0"
                ver = "v6" if intel.is_ipv6 else "v4"
                folium.CircleMarker(
                    location=[intel.lat, intel.lon], radius=10,
                    popup=f"{ip} ({ver})<br>{intel.isp}<br>{intel.city}<br>{intel.country}",
                    color=c, fill=True, fill_color=c
                ).add_to(m)
                if self.capturer:
                    folium.PolyLine(
                        locations=[[lat, lon], [intel.lat, intel.lon]],
                        color=c, weight=2, opacity=0.6
                    ).add_to(m)
            self._map_html = m._repr_html_()
            self.web_view.setHtml(self._map_html, QUrl("about:blank"))
        except Exception as e:
            logger.error("Map render error: %s", e)

    def _update_map_table(self) -> None:
        if hasattr(self, "web_view") and HAS_WEBENGINE and HAS_FOLIUM:
            self._render_map()
            return
        if not hasattr(self, "map_location_table"):
            return
        self.map_location_table.setRowCount(0)
        if self.capturer:
            ana = self.capturer.analyzer
            row = self.map_location_table.rowCount()
            self.map_location_table.insertRow(row)
            vals = ["YOUR IP", "LOCAL", ana.my_isp,
                    "", "", f"{ana.my_lat:.4f}", f"{ana.my_lon:.4f}"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                item.setForeground(QColor("#0ff"))
                self.map_location_table.setItem(row, c, item)
        for ip, data in self.all_data.items():
            intel = data.get("intel")
            if not intel:
                continue
            ip_type = data.get("type", "UNKNOWN")
            color = QColor("#0f0") if ip_type == "P2P_PEER" else QColor("#fa0")
            row = self.map_location_table.rowCount()
            self.map_location_table.insertRow(row)
            vals = [ip, ip_type, intel.isp, intel.city, intel.country,
                    f"{intel.lat:.4f}" if intel.lat else "N/A",
                    f"{intel.lon:.4f}" if intel.lon else "N/A"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                item.setForeground(color)
                self.map_location_table.setItem(row, c, item)

    def _open_map_in_browser(self) -> None:
        if not HAS_FOLIUM:
            QMessageBox.information(self, "Map",
                                    "folium not installed.\npip install folium")
            return
        try:
            import folium
            import tempfile
            lat = self.capturer.analyzer.my_lat if self.capturer else 20.0
            lon = self.capturer.analyzer.my_lon if self.capturer else 0.0
            my_ip = self.capturer.analyzer.my_public_ip if self.capturer else "N/A"
            m = folium.Map(location=[lat, lon], zoom_start=2,
                           tiles="CartoDB dark_matter")
            if self.capturer:
                folium.CircleMarker(
                    location=[lat, lon], radius=12,
                    popup=f"<b>YOU</b><br>{my_ip}",
                    color="cyan", fill=True, fill_color="cyan"
                ).add_to(m)
            for ip, data in self.all_data.items():
                intel = data.get("intel")
                if not intel or (intel.lat == 0 and intel.lon == 0):
                    continue
                c = "#0f0" if data.get("type") == "P2P_PEER" else "#fa0"
                ver = "v6" if intel.is_ipv6 else "v4"
                folium.CircleMarker(
                    location=[intel.lat, intel.lon], radius=10,
                    popup=f"{ip} ({ver})<br>{intel.isp}<br>{intel.city}<br>{intel.country}",
                    color=c, fill=True, fill_color=c
                ).add_to(m)
                if self.capturer:
                    folium.PolyLine(
                        locations=[[lat, lon], [intel.lat, intel.lon]],
                        color=c, weight=2, opacity=0.6
                    ).add_to(m)
            tmp = os.path.join(tempfile.gettempdir(), "voip_analyzer_map.html")
            m.save(tmp)
            QDesktopServices.openUrl(QUrl.fromLocalFile(tmp))
            self._log(f"Map opened: {tmp}")
        except Exception as e:
            logger.error("Map error: %s", e)
            QMessageBox.critical(self, "Map Error", str(e))

    def _export_report(self) -> None:
        if not self.all_data:
            QMessageBox.information(self, "Export", "No data to export.")
            return

        formats = ["CSV (*.csv)", "JSON (*.json)", "HTML (*.html)"]
        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Report", "voip_report", ";;".join(formats))
        if not path:
            return

        report = self.capturer.get_report() if self.capturer else SessionReport()
        success = False
        if selected_filter.startswith("CSV"):
            if not path.endswith(".csv"):
                path += ".csv"
            success = CsvExporter().export(report, self.all_data, path)
        elif selected_filter.startswith("JSON"):
            if not path.endswith(".json"):
                path += ".json"
            success = JsonExporter().export(report, self.all_data, path)
        elif selected_filter.startswith("HTML"):
            if not path.endswith(".html"):
                path += ".html"
            success = HtmlExporter().export(report, self.all_data, path)

        if success:
            self._log(f"Exported to: {path}")
            QMessageBox.information(self, "Export", f"Saved to:\n{path}")
        else:
            self._log(f"Export failed: {path}")

    def _apply_theme(self, theme_name: str) -> None:
        self.config.theme = theme_name
        ThemeEngine.apply(QApplication.instance(), theme_name)
        self.config.save()
        self._log(f"Theme: {theme_name}")

    def _cleanup_cache(self) -> None:
        removed = self.cache_repo.cleanup()
        if removed > 0:
            self._log(f"Cache cleanup: {removed} entries removed")

    def _retention_cleanup(self) -> None:
        days = self.config.data_retention_days
        if days > 0:
            removed = self.session_repo.delete_older_than(days)
            if removed > 0:
                self._log(f"Data retention: {removed} old sessions purged (> {days} days)")

    def _refresh_map(self) -> None:
        if not self.all_data:
            return
        self._update_map_table()

    def _show_about(self) -> None:
        QMessageBox.about(
            self, "About",
            f"<h2>VoIP Analyzer v{__version__}</h2>"
            f"<p>Network forensics for authorized analysis.</p>"
            f"<p><b>Features:</b> IPv4/IPv6, P2P detection, "
            f"plugin system, SQLite DB, real-time stats.</p>")

    def _show_shortcuts(self) -> None:
        QMessageBox.information(
            self, "Keyboard Shortcuts",
            "<b>F5</b> - Start capture<br>"
            "<b>F6</b> - Stop capture<br>"
            "<b>Ctrl+E</b> - Export report<br>"
            "<b>Ctrl+D</b> - Clear data<br>"
            "<b>Ctrl+Q</b> - Quit<br>"
            "<b>Click IP row</b> - IP details<br>")

    def clear_data(self) -> None:
        self.table.setRowCount(0)
        self.p2p_table.setRowCount(0)
        self.relay_table.setRowCount(0)
        self.all_data.clear()
        self.countries.clear()
        self._last_primary_ip = ""
        self.pkt_lbl.setText("PKT: 0")
        self.mode_lbl.setText("MODE: UNKNOWN")
        self.search_box.clear()
        self.type_filter.setCurrentIndex(0)
        self.proto_filter.setCurrentIndex(0)
        self._log("Data cleared.")
        self._update_map_table()

    def closeEvent(self, event) -> None:
        logger.info("Application closing")
        self._gui_timer.stop()
        self._stats_timer.stop()
        self._cleanup_timer.stop()
        if self.capturer:
            self.capturer.stop()
        self.db.close()
        event.accept()
