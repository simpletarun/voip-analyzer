import logging
import logging.handlers
import os
import sys

from PyQt6.QtWidgets import QApplication, QMessageBox

from src import __version__
from src.config import AppConfig
from src.ui.main_window import VoIPAnalyzerGUI
from src.ui.theme import ThemeEngine

logger = logging.getLogger(__name__)


def setup_logging(config: AppConfig) -> str:
    if getattr(sys, 'frozen', False):
        base_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'Cutter')
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "voip_analyzer.log")

    logger = logging.getLogger("VoIPAnalyzer")
    level = getattr(logging, config.log_level, logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s.%(funcName)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    return log_file


def show_disclaimer() -> bool:
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("LEGAL DISCLAIMER & TERMS OF USE")
    msg.setText("<b>WARNING: FOR AUTHORIZED USE ONLY</b>")
    msg.setInformativeText(
        "This tool is strictly for educational purposes and authorized "
        "network analysis.\n\n"
        "Intercepting, monitoring, or analyzing communications without "
        "explicit consent from all parties is illegal in many jurisdictions.\n\n"
        "By clicking 'Accept', you confirm:\n"
        "- You have the legal right to monitor this network\n"
        "- You comply with all applicable laws\n"
        "- All data is stored locally on your device\n"
        "- Developers assume no liability for misuse\n\n"
        "Privacy: No phone numbers or content are transmitted. "
        "Only public IP metadata is queried from ip-api.com."
    )
    msg.setStandardButtons(
        QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
    msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
    return msg.exec() == QMessageBox.StandardButton.Ok


def create_app(config: AppConfig | None = None) -> QApplication:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    if config is None:
        config = AppConfig.load()
    ThemeEngine.apply(app, config.theme)
    return app


def run() -> int:
    config = AppConfig.load()
    log_file = setup_logging(config)

    logger.info("=" * 60)
    logger.info("VoIP Analyzer v%s starting", __version__)
    logger.info("=" * 60)

    app = create_app(config)

    if not show_disclaimer():
        return 0

    window = VoIPAnalyzerGUI(config)
    window.show()

    print("=" * 60)
    print(f"  VoIP Analyzer v{__version__}")
    print("=" * 60)
    print("  Run as Administrator / root for packet capture")
    print("  pip install PyQt6 PyQt6-WebEngine scapy requests folium python-dotenv")
    print(f"  Logs: {log_file}")
    print(f"  DB:   {config.db_path}")
    print("=" * 60)

    return app.exec()
