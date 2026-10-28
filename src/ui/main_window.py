import concurrent.futures
import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from re import Pattern

from PyQt6.QtCore import QEvent, QStringListModel, Qt, QTimer, QUrl
from PyQt6.QtGui import QAction, QColor, QDesktopServices, QKeySequence
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QCompleter,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src import __version__
from src.composition import build_stack
from src.config import AppConfig
from src.database.connection import DatabaseConnection
from src.models.ip_info import IPInfo
from src.models.packet import PacketInfo
from src.models.session import SessionReport
from src.plugins.whatsapp import WhatsAppPlugin
from src.services.capturer import PacketCapturer
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

def _safe_compile_regex(pattern: str, timeout: float = 0.5) -> Pattern | None:
    try:
        future = _RE_THREAD.submit(lambda: re.compile(pattern, re.IGNORECASE))
        return future.result(timeout=timeout)
    except Exception:
        return None


_ESRI = "https://server.arcgisonline.com/ArcGIS/rest/services"
_ESRI_ATTR = "© Esri, HERE, Garmin, © OpenStreetMap contributors"

_TILES = {
    # Esri Canvas basemaps: same host as the satellite layer, which is
    # reachable where the CartoDB CDN is blocked.
    "Dark": (f"{_ESRI}/Canvas/World_Dark_Gray_Base/MapServer/tile/{{z}}/{{y}}/{{x}}",
             _ESRI_ATTR),
    "Light": (f"{_ESRI}/Canvas/World_Light_Gray_Base/MapServer/tile/{{z}}/{{y}}/{{x}}",
              _ESRI_ATTR),
    "Street": ("OpenStreetMap", "© OpenStreetMap contributors"),
    "Satellite": (f"{_ESRI}/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}",
                  "© Esri, Maxar, Earthstar Geographics"),
}


_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


# Folium emits a map page that pulls ~8 libraries from CDNs via jsdelivr,
# cdnjs and code.jquery.com. In restricted networks those don't resolve, so
# the map never paints. We vendor the few libraries we actually use and
# inline them, stripping everything else (bootstrap/fontawesome/awesomemarkers,
# none of which Leaflet basic + AntPath need).
_MAP_LOCAL_ASSETS = {
    "leaflet.css": ("css", "link", "leaflet"),
    "leaflet.js": ("js", "script", "leaflet"),
    "jquery-3.7.1.min.js": ("js", "script", "jquery"),
    "leaflet-ant-path.min.js": ("js", "script", "ant-path"),
}
_LINK_RE = re.compile(r'<link[^>]+href="https?://[^"]+"[^>]*>', re.I)
_SCRIPT_RE = re.compile(r'<script[^>]+src="https?://[^"]+"[^>]*>\s*</script>', re.I)


def _localize_map_html(html: str) -> str:
    """Inline locally vendored JS/CSS and drop unused external map resources."""

    def _inline_link(name: str, content: str) -> str:
        # folium uses "<link href='...leaflet.css'>..." (single quotes too)
        pattern = re.compile(
            r'<link[^>]*href=["\']?[^"\']*' + re.escape(name) + r'[^"\']*["\']?[^>]*>',
            re.I,
        )
        return pattern.sub(lambda _m: f"<style>{content}</style>", html, count=1)

    def _inline_script(name: str, content: str) -> str:
        pattern = re.compile(
            r'<script[^>]*src=["\']?[^"\']*' + re.escape(name) + r'[^"\']*["\']?[^>]*>\s*</script>',
            re.I,
        )
        return pattern.sub(lambda _m: f"<script>{content}</script>", html, count=1)

    for name, (kind, _tag, slug) in _MAP_LOCAL_ASSETS.items():
        asset = _ASSETS_DIR / name
        try:
            content = asset.read_text(encoding="utf-8")
        except Exception:
            continue
        if kind == "css":
            html = _inline_link(name, content)
        else:
            html = _inline_script(name, content)
    # Drop whatever external resources were not inlined.
    html = _LINK_RE.sub("", html)
    html = _SCRIPT_RE.sub("", html)
    return html


class VoIPAnalyzerGUI(QMainWindow):
    def __init__(self, config: AppConfig):
        super().__init__()
        self.config = config
        self.db = DatabaseConnection(config.db_path)
        self.stack = build_stack(config, self.db)
        self.session_repo = self.stack.session_repo
        self.peer_repo = self.stack.peer_repo
        self.cache_repo = self.stack.cache_repo
        self.capturer: PacketCapturer | None = None
        self.all_data: dict[str, dict] = {}
        self.countries: set = set()
        self.cities: set = set()
        self._uptime_start: float | None = None
        self._last_primary_ip: str = ""
        self._pkt_buffer: list = []
        self._buf_lock = threading.Lock()
        self._filter_state: tuple = ("", "All", "All", False)
        self._map_signature: str = ""
        self._my_lat: float = 20.0
        self._my_lon: float = 0.0
        self._my_ip: str = "N/A"
        self._has_location: bool = False
        self._map_layout: "QVBoxLayout | None" = None
        self._tile_name: str = "Dark"
        self._map_fs: bool = False
        self._fs_window: "QMainWindow | None" = None
        self._fs_view: "QWebEngineView | None" = None
        self._my_city: str = "Unknown"
        self._my_region: str = "Unknown"
        self._my_country: str = "Unknown"
        # Track IPs actively seen in media traffic (RTP/RTCP) - these are the
        # actual call participant IPs during WhatsApp/Telegram calls
        self._media_ips: set[str] = set()
        self._stun_peer_ips: set[str] = set()
        try:
            from src.services.network_analyzer import NetworkAnalyzer
            self._analyzer = None
            def _init_analyzer():
                try:
                    self._analyzer = NetworkAnalyzer()
                except Exception:
                    self._analyzer = None
            t = threading.Thread(target=_init_analyzer, daemon=True)
            t.start()
        except Exception:
            self._analyzer = None

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

        # Map rebuilds are debounced: a burst of peers triggers one page load
        # instead of one reload per peer.
        self._map_debounce = QTimer()
        self._map_debounce.setSingleShot(True)
        self._map_debounce.timeout.connect(self._render_map_now)

        self._build_ui()
        self._retention_cleanup()
        # Ensure map renders after UI is fully laid out
        QTimer.singleShot(200, self._init_map)
        QTimer.singleShot(800, lambda: self._render_map(force=True))
        QTimer.singleShot(1500, lambda: self._render_map(force=True))

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

        ctrl = QHBoxLayout()
        self.start_btn = QPushButton("START")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setShortcut(QKeySequence())
        ctrl.addWidget(self.start_btn)

        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setShortcut(QKeySequence())
        self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("CLEAR")
        self.clear_btn.clicked.connect(self.clear_data)
        self.clear_btn.setShortcut(QKeySequence())
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
        self._city_model = QStringListModel([])
        self._city_completer = QCompleter(self._city_model, self)
        self._city_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._city_completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self._city_completer.setCompletionMode(
            QCompleter.CompletionMode.PopupCompletion)
        self.search_box.setCompleter(self._city_completer)
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

        self.stun_filter = QCheckBox("STUN only")
        self.stun_filter.setToolTip("Show only STUN packets (NAT traversal / call setup)")
        self.stun_filter.toggled.connect(self._on_filter_changed)
        filter_row.addWidget(self.stun_filter)
        ll.addLayout(filter_row)

        self.table = QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels([
            "#", "TIME", "DIR", "SRC", "DST", "PROTO", "VER",
            "TYPE", "PROTOCOL", "ISP", "CITY", "COUNTRY", "STUN"
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
        self.whois_btn = QPushButton("WHOIS")
        self.whois_btn.clicked.connect(self._whois_selected_ip)
        self.whois_btn.setEnabled(HAS_WHOIS)
        self.whois_btn.setShortcut(QKeySequence())
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
        map_header = QHBoxLayout()
        map_header.addWidget(QLabel("Map Style:"))
        self.tile_combo = QComboBox()
        self.tile_combo.addItems(["Dark", "Satellite", "Street", "Light"])
        self.tile_combo.setCurrentText(self._tile_name)
        self.tile_combo.currentTextChanged.connect(self._on_tile_changed)
        map_header.addWidget(self.tile_combo)
        self.fullscreen_btn = QPushButton("Full Screen")
        self.fullscreen_btn.clicked.connect(self._toggle_map_fullscreen)
        self.fullscreen_btn.setShortcut(QKeySequence())
        map_header.addWidget(self.fullscreen_btn)
        map_header.addStretch()
        ml.addLayout(map_header)

        legend = QLabel(
            "<span style='color:#0f0;'>&#9679;</span> P2P Peer &nbsp;&nbsp; "
            "<span style='color:#fa0;'>&#9679;</span> Relay Server")
        legend.setStyleSheet(
            "padding:4px 8px; background:#001a1a; border:1px solid #0a4; "
            "color:#0f0; font-weight:bold;")
        ml.addWidget(legend)

        if HAS_WEBENGINE and HAS_FOLIUM:
            self._map_layout = ml
            self.web_view = QWebEngineView()
            self.web_view.setMinimumHeight(400)
            self.web_view.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            frame = QFrame()
            frame.setFrameShape(QFrame.Shape.StyledPanel)
            frame.setStyleSheet(
                "QFrame{border:2px solid #0ff; border-radius:4px;}")
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(2, 2, 2, 2)
            fl.addWidget(self.web_view)
            ml.addWidget(frame, 1)
            self.web_view.installEventFilter(self)
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
        self._map_tab_index = self.tabs.indexOf(mw)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.tabs.setCurrentIndex(self._map_tab_index)

        rl.addWidget(self.tabs)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([400, 700])
        root.addWidget(splitter)

        self._progress = QProgressBar()
        self._progress.setMaximum(0)
        self._progress.setMaximumWidth(180)
        self._progress.setVisible(False)
        self.statusBar().addPermanentWidget(self._progress)

        # All result grids are read-only: a double-click must not edit cells.
        for table in (self.table, self.p2p_table, self.relay_table,
                      self.history_table,
                      getattr(self, "map_location_table", None)):
            if table is not None:
                table.setEditTriggers(
                    QAbstractItemView.EditTrigger.NoEditTriggers)

        self._build_menu()
        self.statusBar().showMessage(
            f"v{__version__} | DB: {self.config.db_path} | "
            f"Cache TTL: {self.config.cache_ttl_hours}h")

        self._log("Analyzer initialized.")
        self._log(f"Version: {__version__}")
        if not HAS_SCAPY:
            self._log("WARNING: Scapy not installed - capture disabled")
        self._load_session_history()
        if HAS_FOLIUM:
            self._init_map()
            QTimer.singleShot(0, lambda: self._render_map(force=True))
            QTimer.singleShot(400, lambda: self._render_map(force=True))
            QTimer.singleShot(1000, lambda: self._render_map(force=True))

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        export_action = QAction("Export Report...", self)
        export_action.triggered.connect(self._export_report)
        export_action.setShortcut(QKeySequence())
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        quit_action.setShortcut(QKeySequence())
        file_menu.addAction(quit_action)

        view_menu = menubar.addMenu("View")
        theme_menu = view_menu.addMenu("Theme")
        for theme_name in ThemeEngine.THEMES:
            action = QAction(theme_name.capitalize(), self)
            action.triggered.connect(lambda checked, t=theme_name: self._apply_theme(t))
            theme_menu.addAction(action)

        cleanup_action = QAction("Cleanup Cache", self)
        cleanup_action.triggered.connect(self._cleanup_cache)
        view_menu.addAction(cleanup_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{ts}] {msg}")
        logger.info(msg)

    def start_capture(self) -> None:
        if self.capturer and getattr(self.capturer, "running", False):
            return
        if not HAS_SCAPY:
            QMessageBox.critical(self, "Error", "Scapy is not installed.")
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("STARTING")
        self.status_lbl.setStyleSheet("color: #ff0; font-weight: bold;")
        self._log("Starting capture...")

        def _start():
            try:
                capturer = PacketCapturer(
                    self.config, self.session_repo, self.peer_repo,
                    self.stack.ip_intel, analyzer=getattr(self, "_analyzer", None))
                capturer.on("packet", self._on_packet)
                capturer.on("new_peer", lambda *a: self._enqueue_ui_event("_on_new_peer", *a))
                capturer.on("peer_update", lambda *a: self._enqueue_ui_event("_on_peer_update", *a))
                capturer.on("status", lambda *a: self._enqueue_ui_event("_on_status", *a))
                capturer.on("log", lambda *a: self._enqueue_ui_event("_log", *a))
                capturer.on("error", lambda *a: self._enqueue_ui_event("_on_error", *a))
                self.capturer = capturer
                self._capture_thread = threading.Thread(
                    target=capturer.run, daemon=True, name="Capture")
                self._capture_thread.start()
                self._enqueue_ui_event("_on_capture_started")
            except Exception as e:
                logger.exception("Failed to start capture")
                self.capturer = None
                self._enqueue_ui_event("_on_capture_failed", str(e))

        threading.Thread(target=_start, daemon=True, name="StartCapture").start()

    def _on_capture_started(self) -> None:
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText("CAPTURING")
        self.status_lbl.setStyleSheet("color: #0f0; font-weight: bold;")
        self._uptime_start = time.time()
        self._log("Capture started.")

    def _on_capture_failed(self, msg: str) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("READY")
        self.status_lbl.setStyleSheet("color: #ff0; font-weight: bold;")
        self._log(f"ERROR: {msg}")

    def stop_capture(self) -> None:
        try:
            if not self.capturer:
                try:
                    if hasattr(self, "start_btn"):
                        self.start_btn.setEnabled(True)
                    if hasattr(self, "stop_btn"):
                        self.stop_btn.setEnabled(False)
                    if hasattr(self, "status_lbl"):
                        self.status_lbl.setText("STOPPED")
                        self.status_lbl.setStyleSheet("color: #f00; font-weight: bold;")
                    self._uptime_start = None
                except Exception:
                    pass
                return
            try:
                self.capturer.stop()
            except Exception:
                logger.exception("Error stopping capturer")

            try:
                report = self.capturer.get_report()
            except Exception:
                logger.exception("Error getting report")
                report = SessionReport()

            try:
                session_id = self.session_repo.save(report)
            except Exception:
                logger.exception("Error saving session")
                session_id = None

            try:
                top_ip, top_score, top_isp = "N/A", 0, ""
                for ip, d in getattr(self, "all_data", {}).items():
                    s = d.get("score", 0) if isinstance(d, dict) else 0
                    if s > top_score:
                        top_ip = ip
                        top_score = s
                        intel = d.get("intel") if isinstance(d, dict) else None
                        try:
                            if intel and getattr(intel, "isp", None) not in ("Unknown", ""):
                                top_isp = f" | {intel.isp}"
                            else:
                                top_isp = ""
                        except Exception:
                            top_isp = ""
                self._log("=" * 58)
                self._log("SESSION REPORT")
                self._log(f"Session ID: {session_id}")
                self._log(f"Duration: {getattr(report, 'duration_seconds', 0):.1f}s")
                self._log(f"Packets: {getattr(report, 'total_packets', 0)}")
                self._log(f"Bytes: {getattr(report, 'total_bytes', 0):,}")
                self._log(f"P2P: {getattr(report, 'p2p_count', 0)} | Relay: {getattr(report, 'relay_count', 0)}")
                self._log(f"Call IP: {top_ip}{top_isp} (confidence: {top_score}%)")
                try:
                    countries = getattr(report, "countries", []) or []
                    self._log(f"Countries: {', '.join(countries) or 'N/A'}")
                except Exception:
                    pass
                self._log("=" * 58)
            except Exception:
                logger.exception("Error logging report")

            try:
                if hasattr(self, "start_btn"):
                    self.start_btn.setEnabled(True)
                if hasattr(self, "stop_btn"):
                    self.stop_btn.setEnabled(False)
                if hasattr(self, "status_lbl"):
                    self.status_lbl.setText("STOPPED")
                    self.status_lbl.setStyleSheet("color: #f00; font-weight: bold;")
            except Exception:
                pass
            self._uptime_start = None
            self.capturer = None
            try:
                self._load_session_history()
            except Exception:
                logger.exception("Error loading session history")
        except Exception:
            logger.exception("stop_capture crashed")
            try:
                if hasattr(self, "start_btn"):
                    self.start_btn.setEnabled(True)
                if hasattr(self, "stop_btn"):
                    self.stop_btn.setEnabled(False)
                if hasattr(self, "status_lbl"):
                    self.status_lbl.setText("STOPPED")
                    self.status_lbl.setStyleSheet("color: #f00; font-weight: bold;")
            except Exception:
                pass
            self._uptime_start = None
            self.capturer = None

    def _on_packet(self, pkt_info: PacketInfo) -> None:
        # Track media endpoints for map - WhatsApp/Telegram calls use RTP/RTCP
        try:
            pname = getattr(pkt_info, "protocol_name", "") or ""
            if pname in ("RTP", "RTCP", "STUN", "TURN"):
                src = getattr(pkt_info, "src", "")
                dst = getattr(pkt_info, "dst", "")
                for ip in (src, dst):
                    if ip and ip not in ("0.0.0.0", "::", "127.0.0.1", "localhost", ""):
                        if not self._is_local_ip(ip):
                            self._media_ips.add(ip)
                            if pname in ("STUN", "TURN"):
                                self._stun_peer_ips.add(ip)
            # Also check stun_info for peer addresses
            stun_info = getattr(pkt_info, "stun_info", "") or ""
            if stun_info and ("peer" in stun_info.lower() or "relayed" in stun_info.lower()):
                import re as _re
                for m in _re.findall(r'(\d+\.\d+\.\d+\.\d+):\d+', stun_info):
                    if not self._is_local_ip(m):
                        self._stun_peer_ips.add(m)
                        self._media_ips.add(m)
        except Exception:
            pass
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
            if len(batch) > 500:
                # cap work per tick; keep the rest for the next flush
                self._pkt_buffer = batch[500:]
                batch = batch[:500]

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
                    pkt.isp, pkt.city, pkt.country,
                    getattr(pkt, "stun_info", ""),
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
        if (self.search_box.text().strip()
                or self.type_filter.currentText() != "All"
                or self.proto_filter.currentText() != "All"
                or self.stun_filter.isChecked()):
            self._apply_filter()

    def _is_local_ip(self, ip: str) -> bool:
        try:
            if getattr(self, "_analyzer", None) and self._analyzer.is_my_ip(ip):
                return True
        except Exception:
            pass
        return False

    def _on_new_peer(self, ip: str, intel: IPInfo, stats: dict, ip_type: str) -> None:
        if self._is_local_ip(ip):
            return
        self.all_data[ip] = {"intel": intel, "stats": stats, "type": ip_type, "score": 0}
        self._log(f"NEW IP: {ip} (resolving...)")

    def _on_peer_update(self, ip: str, intel: IPInfo, stats: dict, ip_type: str) -> None:
        if self._is_local_ip(ip):
            try:
                if ip in self.all_data:
                    self.all_data.pop(ip, None)
                for tbl in (self.p2p_table, self.relay_table):
                    r = self._find_ip_row(tbl, ip)
                    if r >= 0:
                        tbl.removeRow(r)
                self._refresh_packet_table_ip(ip, intel)
            except Exception:
                pass
            return
        old = self.all_data.get(ip, {})
        old_type = old.get("type", "UNKNOWN")
        score = WhatsAppPlugin.peer_confidence(intel, stats)

        if ip_type == "P2P_PEER":
            table = self.p2p_table
            color = QColor("#0f0")
            if old_type != "P2P_PEER":
                self._log(f"P2P PEER: {ip} | {intel.isp} (confidence: {score}%)")
        elif ip_type == "RELAY":
            table = self.relay_table
            color = QColor("#fa0")
            if old_type != "RELAY":
                self._log(f"RELAY: {ip} | {intel.isp}")
        else:
            # Don't skip - could be call participant
            table = self.relay_table
            color = QColor("#888")

        row = self._find_ip_row(table, ip)
        if row < 0:
            row = table.rowCount()
            table.insertRow(row)

        is_p2p = (table is self.p2p_table)
        self._update_ip_row(table, row, ip, intel, stats, color, score)
        # Force show on map if seen in media/STUN
        if ip in getattr(self, "_media_ips", set()) or getattr(self, "_stun_peer_ips", set()) and ip in getattr(self, "_stun_peer_ips", set()):
            if ip_type != "P2P_PEER":
                ip_type = "P2P_PEER"
        self.all_data[ip] = {"intel": intel, "stats": stats, "type": ip_type, "score": score}

        if is_p2p:
            self._sort_p2p_table()
            self._update_p2p_header()
            self._recolor_p2p_table()

        self._refresh_packet_table_ip(ip, intel)
        self._update_map_table()
        self._render_map(force=True)

        country = intel.country
        if country and country not in ("Unknown", "...") and country not in self.countries:
            self.countries.add(country)
        city = intel.city
        if city and city not in ("Unknown", "..."):
            if city not in self.cities:
                self.cities.add(city)
                self._refresh_city_completer()

    def _refresh_city_completer(self) -> None:
        try:
            self._city_model.setStringList(sorted(self.cities))
            self._city_completer.setModel(self._city_model)
        except Exception:
            pass

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
        try:
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
        except Exception:
            pass

    @staticmethod
    def _find_ip_row(table: QTableWidget, ip: str) -> int:
        for r in range(table.rowCount()):
            item = table.item(r, 0)
            if item and item.text() == ip:
                return r
        return -1

    @staticmethod
    def _update_ip_row(table: QTableWidget, row: int, ip: str,
                       intel: IPInfo, stats: dict, color: QColor,
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
                     self.proto_filter.currentText(), self.stun_filter.isChecked())
        if new_state != self._filter_state:
            self._filter_state = new_state
            self._apply_filter()
            self._render_map()

    def _apply_filter(self) -> None:
        text = self.search_box.text().strip()
        type_text = self.type_filter.currentText()
        proto_text = self.proto_filter.currentText()
        stun_only = self.stun_filter.isChecked()

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
                if (not text and type_text == "All" and proto_text == "All"
                        and not stun_only):
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

                stun_match = True
                if stun_only and table == self.table:
                    # TYPE column carries the "STUN" marker (e.g. "P2P_PEER STUN")
                    item = table.item(row, 7)
                    stun_match = bool(item and "STUN" in item.text().upper())

                table.setRowHidden(row, not (text_match and type_match
                                             and proto_match and stun_match))

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

    def _map_signature_str(self) -> str:
        parts = []
        analyzer = self.capturer.analyzer if self.capturer else None
        for ip in sorted(self.all_data):
            if analyzer and analyzer.is_my_ip(ip):
                continue
            data = self.all_data[ip]
            intel = data.get("intel")
            if not intel:
                continue
            if getattr(intel, "lat", 0) == 0 and getattr(intel, "lon", 0) == 0:
                continue
            parts.append(f"{ip}:{data.get('type')}:{intel.lat:.4f}:{intel.lon:.4f}")
        return (f"{self.search_box.text()}|{self.type_filter.currentText()}|"
                + "|".join(parts))

    def _render_map(self, force: bool = False) -> None:
        if not (HAS_WEBENGINE and HAS_FOLIUM):
            return
        if not force and getattr(self, "_map_tab_index", -1) != self.tabs.currentIndex():
            return
        sig = self._map_signature_str() + f"|tile:{self._tile_name}"
        if not force and sig == self._map_signature:
            return
        self._map_signature = sig
        if force:
            self._render_map_now()
        else:
            # Coalesce rapid signature changes (e.g. many peers resolving)
            # into a single page reload.
            self._map_debounce.stop()
            self._map_debounce.start(800)

    def _render_map_now(self) -> None:
        """Build + inject the map HTML into the WebEngine view."""
        try:
            m = self._build_folium_map(zoom=3)
            # Raw page HTML: _repr_html_ wraps it in a Jupyter iframe whose
            # fallback text is "Make this Notebook Trusted to load map".
            html = _localize_map_html(m.get_root().render())
            self._map_html = html
            try:
                if hasattr(self, "web_view"):
                    self.web_view.setHtml(html, QUrl("http://localhost/"))
            except Exception:
                pass
            fs_view = getattr(self, "_fs_view", None)
            if fs_view is not None:
                try:
                    fs_view.setHtml(html, QUrl("http://localhost/"))
                except Exception:
                    pass
        except Exception as e:
            logger.error("Map render error: %s", e)

    def _map_nodes(self) -> list[tuple[str, float, float, str, object]]:
        """Show EXACTLY the same IP as the top row in P2P PEERS table."""
        analyzer = self.capturer.analyzer if self.capturer else None
        call_ip = None

        # Match 1:1 with P2P PEERS panel - take the top peer
        try:
            if hasattr(self, "p2p_table") and self.p2p_table.rowCount() > 0:
                ip_item = self.p2p_table.item(0, 0)
                if ip_item:
                    cand = ip_item.text().strip()
                    if cand and cand not in ("", "N/A"):
                        if self._is_local_ip(cand):
                            pass
                        elif analyzer and analyzer.is_my_ip(cand):
                            pass
                        else:
                            call_ip = cand
        except Exception:
            pass

        # Match 2: fallback to capturer's detected call peer
        if not call_ip and self.capturer:
            try:
                for cip in getattr(self.capturer, "_call_peer_ips", set()) | getattr(self.capturer, "_p2p_candidates", set()) | getattr(self.capturer, "_forced_types", {}).keys():
                    if not cip:
                        continue
                    if self._is_local_ip(cip):
                        continue
                    if analyzer and analyzer.is_my_ip(cip):
                        continue
                    # Prefer one that exists in p2p/all_data as P2P_PEER
                    if cip in self.all_data and self.all_data[cip].get("type") == "P2P_PEER":
                        call_ip = cip
                        break
                if not call_ip:
                    for cip in getattr(self.capturer, "_p2p_candidates", set()):
                        if cip and not self._is_local_ip(cip) and not (analyzer and analyzer.is_my_ip(cip)):
                            call_ip = cip
                            break
            except Exception:
                pass

        if not call_ip:
            return []

        # Ensure intel exists for this IP
        try:
            ip_intel = getattr(self.stack, "ip_intel", None)
            if call_ip not in self.all_data and ip_intel:
                try:
                    intel = ip_intel.get_intel(call_ip)
                    if intel:
                        self.all_data[call_ip] = {"intel": intel, "stats": {"packets": 1}, "type": "P2P_PEER", "score": 100}
                        self._on_peer_update(call_ip, intel, {"packets": 1, "bytes": 0, "inbound": 0, "outbound": 0}, "P2P_PEER")
                except Exception:
                    pass
        except Exception:
            pass

        data = self.all_data.get(call_ip)
        if not data:
            return []
        intel = data.get("intel")
        if not intel:
            return []
        if (getattr(intel, "lat", 0) == 0 and getattr(intel, "lon", 0) == 0):
            return []
        if self._is_local_ip(call_ip):
            return []
        if analyzer and analyzer.is_my_ip(call_ip):
            return []

        return [(call_ip, intel.lat, intel.lon, "P2P_PEER", intel)]

    def _draw_flows(self, m, nodes: list) -> None:
        """Draw traffic-flow lines between the remote nodes on the map."""
        peers = [n for n in nodes if n[3] == "P2P_PEER"]
        relays = [n for n in nodes if n[3] != "P2P_PEER"]
        segments = []
        if relays and peers:
            # Calls are carried through the relay servers, so link each
            # peer to each relay.
            for peer in peers:
                for relay in relays:
                    if len(segments) >= 150:
                        break
                    segments.append((relay, peer, "#fa0", "peer ↔ relay"))
        elif len(peers) > 1:
            # Direct P2P call: show the call group as a mesh.
            for i, a in enumerate(peers):
                for b in peers[i + 1:]:
                    if len(segments) >= 150:
                        break
                    segments.append((a, b, "#0f0", "peer ↔ peer"))
        if not segments and len(nodes) > 1:
            for a, b in zip(nodes, nodes[1:]):
                segments.append((a, b, "#0ff", "remote ↔ remote"))

        ant_path = None
        try:
            from folium.plugins import AntPath
            ant_path = AntPath
        except Exception:
            ant_path = None
        for a, b, color, label in segments:
            pts = [[a[1], a[2]], [b[1], b[2]]]
            tip = f"{label}: {a[0]} ↔ {b[0]}"
            try:
                if ant_path is not None:
                    ant_path(pts, color=color, weight=2, opacity=0.75,
                             delay=900, dash_array="10,20",
                             tooltip=tip).add_to(m)
                else:
                    folium.PolyLine(pts, color=color, weight=1.5,
                                    opacity=0.55, tooltip=tip).add_to(m)
            except Exception:
                try:
                    folium.PolyLine(pts, color=color, weight=1.5,
                                    opacity=0.55).add_to(m)
                except Exception:
                    pass

    def _build_folium_map(self, zoom: int = 3):
        """Build the map for the current data, with style + flow lines."""
        nodes = self._map_nodes()
        tiles, attr = self._tile_for(self._tile_name)
        if nodes:
            center = [sum(n[1] for n in nodes) / len(nodes),
                      sum(n[2] for n in nodes) / len(nodes)]
        else:
            center, zoom = [20.0, 0.0], 2
        try:
            m = folium.Map(location=center, zoom_start=zoom, tiles=tiles, attr=attr)
        except Exception:
            m = folium.Map(location=center, zoom_start=zoom)

        self._draw_flows(m, nodes)
        for ip, lat, lon, ip_type, intel in nodes:
            c = "#0f0" if ip_type == "P2P_PEER" else "#fa0"
            ver = "v6" if getattr(intel, "is_ipv6", False) else "v4"
            popup = (f"{ip} ({ver})<br>{getattr(intel, 'isp', '')}"
                     f"<br>{getattr(intel, 'city', '')}"
                     f"<br>{getattr(intel, 'country', '')}")
            try:
                folium.CircleMarker(
                    location=[lat, lon], radius=8, popup=popup,
                    color=c, fill=True, fill_color=c,
                ).add_to(m)
            except Exception:
                pass
        return m

    @staticmethod
    def _tile_for(name: str) -> tuple[str, str]:
        if name in _TILES:
            return _TILES[name]
        return ("OpenStreetMap", "© OpenStreetMap contributors")

    def _on_tile_changed(self, name: str) -> None:
        self._tile_name = name
        self._render_map(force=True)

    def _on_tab_changed(self, index: int) -> None:
        if getattr(self, "_map_tab_index", -1) == index:
            self._render_map(force=True)

    def _toggle_map_fullscreen(self) -> None:
        if not getattr(self, "web_view", None):
            return
        if self._map_fs:
            self._exit_map_fullscreen()
            return
        fs = QWidget()
        fs.setWindowTitle("Map - Full Screen  (Esc to exit)")
        fs.setWindowFlag(Qt.WindowType.Window)
        container = QVBoxLayout(fs)
        container.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        bar.setContentsMargins(8, 6, 8, 6)
        bar.addWidget(QLabel(
            "<b style='color:#0ff;'>MAP &mdash; FULL SCREEN</b>"))
        bar.addStretch()
        exit_btn = QPushButton("✕ Exit Full Screen (Esc)")
        exit_btn.clicked.connect(self._exit_map_fullscreen)
        bar.addWidget(exit_btn)
        container.addLayout(bar)
        view = QWebEngineView()
        view.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        container.addWidget(view, 1)
        fs.installEventFilter(self)
        self._fs_window = fs
        self._fs_view = view
        self._map_fs = True
        fs.showFullScreen()
        # Render only AFTER the window is laid out, otherwise Leaflet
        # initializes at 0x0 and the map stays blank.
        QTimer.singleShot(40, self._push_fs_html)

    def _push_fs_html(self) -> None:
        if not self._map_fs or self._fs_view is None:
            return
        self._render_map(force=True)

    def _exit_map_fullscreen(self) -> None:
        if not self._map_fs:
            return
        if self._fs_window is not None:
            self._fs_window.close()
            self._fs_window = None
            self._fs_view = None
        self._map_fs = False

    def eventFilter(self, obj, event) -> bool:
        if event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Escape and self._map_fs:
                self._exit_map_fullscreen()
                return True
            if event.key() == Qt.Key.Key_F and self._map_fs:
                self._toggle_map_fullscreen()
                return True
        return super().eventFilter(obj, event)

    def _update_map_table(self) -> None:
        if hasattr(self, "web_view") and HAS_WEBENGINE and HAS_FOLIUM:
            self._render_map()
            return
        if not hasattr(self, "map_location_table"):
            return
        self.map_location_table.setRowCount(0)
        analyzer = self.capturer.analyzer if self.capturer else None
        for ip, data in self.all_data.items():
            if analyzer and analyzer.is_my_ip(ip):
                continue
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
            import tempfile
            m = self._build_folium_map(zoom=2)
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

        formats = ["CSV (*.csv)", "JSON (*.json)", "HTML (*.html)",
                   "Markdown (*.md)", "Excel (*.xlsx)", "PDF (*.pdf)"]
        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Report", "voip_report", ";;".join(formats))
        if not path:
            return

        self._progress.setVisible(True)
        self._progress.setRange(0, 0)
        QApplication.processEvents()
        try:
            report = self.capturer.get_report() if self.capturer else SessionReport()
            success = False
            if selected_filter.startswith("CSV"):
                if not path.endswith(".csv"):
                    path += ".csv"
                from src.export.csv_exporter import CsvExporter
                success = CsvExporter().export(report, self.all_data, path)
            elif selected_filter.startswith("JSON"):
                if not path.endswith(".json"):
                    path += ".json"
                from src.export.json_exporter import JsonExporter
                success = JsonExporter().export(report, self.all_data, path)
            elif selected_filter.startswith("HTML"):
                if not path.endswith(".html"):
                    path += ".html"
                from src.export.html_exporter import HtmlExporter
                success = HtmlExporter().export(report, self.all_data, path)
            elif selected_filter.startswith("Markdown"):
                if not path.endswith(".md"):
                    path += ".md"
                from src.export.markdown_exporter import MarkdownExporter
                success = MarkdownExporter().export(report, self.all_data, path)
            elif selected_filter.startswith("Excel"):
                if not path.endswith(".xlsx"):
                    path += ".xlsx"
                from src.export.excel_exporter import ExcelExporter
                success = ExcelExporter().export(report, self.all_data, path)
            elif selected_filter.startswith("PDF"):
                if not path.endswith(".pdf"):
                    path += ".pdf"
                from src.export.pdf_exporter import PdfExporter
                success = PdfExporter().export(report, self.all_data, path)

            if success:
                self._log(f"Exported to: {path}")
                self.statusBar().showMessage(f"Exported: {path}")
                QMessageBox.information(self, "Export", f"Saved to:\n{path}")
            else:
                self._log(f"Export failed: {path}")
                QMessageBox.warning(self, "Export", "Export failed. Check logs.")
        finally:
            self._progress.setVisible(False)

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
        days = getattr(self.config, "data_retention_days", 0)
        if days > 0:
            try:
                removed = self.session_repo.delete_older_than(days)
                if removed > 0 and hasattr(self, "console") and self.console is not None:
                    self._log(f"Data retention: {removed} old sessions purged (> {days} days)")
            except Exception:
                pass

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

    def clear_data(self) -> None:
        self.table.setRowCount(0)
        self.p2p_table.setRowCount(0)
        self.relay_table.setRowCount(0)
        self.all_data.clear()
        self.countries.clear()
        self.cities.clear()
        self._refresh_city_completer()
        self._last_primary_ip = ""
        self.pkt_lbl.setText("PKT: 0")
        self.mode_lbl.setText("MODE: UNKNOWN")
        self.search_box.clear()
        self.type_filter.setCurrentIndex(0)
        self.proto_filter.setCurrentIndex(0)
        self.stun_filter.setChecked(False)
        self._log("Data cleared.")
        self._update_map_table()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # MAP is the start tab: its first render happens while hidden, so
        # re-render once the widget has a real size (0x0 Leaflet otherwise).
        if not getattr(self, "_shown_once", False):
            self._shown_once = True
            if self._map_tab_index == self.tabs.currentIndex():
                QTimer.singleShot(0, lambda: self._render_map(force=True))

    def closeEvent(self, event) -> None:
        logger.info("Application closing")
        try:
            self._gui_timer.stop()
            self._stats_timer.stop()
            self._cleanup_timer.stop()
            if hasattr(self, "_map_timer"):
                self._map_timer.stop()
            if hasattr(self, "_map_debounce"):
                self._map_debounce.stop()
        except Exception:
            pass
        try:
            if self.capturer:
                self.capturer.stop()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        event.accept()
