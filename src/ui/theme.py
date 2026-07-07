import logging
import os
from typing import Optional

from PyQt6.QtWidgets import QApplication

logger = logging.getLogger(__name__)

DARK_THEME = """
    QMainWindow, QWidget { background: #000; color: #0f0;
                           font-family: 'Consolas', monospace; }
    QLabel { color: #0f0; }
    QPushButton { background: #001a00; color: #0f0;
                  border: 2px solid #0f0; padding: 10px; font-weight: bold; }
    QPushButton:hover { background: #0f0; color: #000; }
    QPushButton#stopBtn { background: #f00; border-color: #f00; color: #fff; }
    QTableWidget { background: #000500; color: #0f0;
                   gridline-color: #004400; border: 2px solid #0f0; }
    QHeaderView::section { background: #001a00; color: #0f0;
                           border: 1px solid #0f0; padding: 6px; }
    QPlainTextEdit { background: #000500; color: #0f0; border: 1px solid #0f0; }
    QLineEdit { background: #001a00; color: #0f0;
                border: 2px solid #0f0; padding: 8px; }
    QComboBox { background: #001a00; color: #0f0;
                border: 1px solid #0f0; padding: 4px; }
    QComboBox QAbstractItemView { background: #001a00; color: #0f0;
                                  selection-background-color: #0f0; selection-color: #000; }
    QTabWidget::pane { border: 2px solid #0f0; }
    QTabBar::tab { background: #001a00; color: #0f0;
                   border: 1px solid #0f0; padding: 8px 16px; }
    QTabBar::tab:selected { background: #0f0; color: #000; }
    QMenuBar { background: #001a00; color: #0f0; }
    QMenuBar::item:selected { background: #0f0; color: #000; }
    QMenu { background: #001a00; color: #0f0; border: 1px solid #0f0; }
    QStatusBar { background: #001a00; color: #0f0; }
    QDialog { background: #000; color: #0f0; }
    QGroupBox { color: #0f0; border: 1px solid #0f0; margin-top: 10px; padding-top: 15px; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
    QScrollArea { border: none; }
    QFrame#stats_frame { background: #001a00; border: 1px solid #0f0; border-radius: 5px; }
"""

LIGHT_THEME = """
    QMainWindow, QWidget { background: #fff; color: #000;
                           font-family: 'Segoe UI', sans-serif; }
    QLabel { color: #000; }
    QPushButton { background: #e0e0e0; color: #000;
                  border: 1px solid #999; padding: 8px; }
    QPushButton:hover { background: #0066cc; color: #fff; }
    QPushButton#stopBtn { background: #cc0000; color: #fff; border-color: #990000; }
    QTableWidget { background: #fff; color: #000;
                   gridline-color: #ddd; border: 1px solid #999; }
    QHeaderView::section { background: #f0f0f0; color: #000;
                           border: 1px solid #999; padding: 6px; }
    QPlainTextEdit { background: #fafafa; color: #000; border: 1px solid #999; }
    QLineEdit { background: #fff; color: #000;
                border: 1px solid #999; padding: 6px; }
    QComboBox { background: #fff; color: #000; border: 1px solid #999; padding: 4px; }
    QTabWidget::pane { border: 1px solid #999; }
    QTabBar::tab { background: #f0f0f0; color: #000;
                   border: 1px solid #999; padding: 8px 16px; }
    QTabBar::tab:selected { background: #0066cc; color: #fff; }
    QMenuBar { background: #f0f0f0; color: #000; }
    QStatusBar { background: #f0f0f0; color: #000; }
    QDialog { background: #fff; color: #000; }
    QGroupBox { color: #000; border: 1px solid #999; }
    QFrame#stats_frame { background: #f5f5f5; border: 1px solid #999; border-radius: 5px; }
"""


class ThemeEngine:
    THEMES = {
        "dark": DARK_THEME,
        "light": LIGHT_THEME,
    }

    @classmethod
    def load_from_file(cls, path: str) -> Optional[str]:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
        except OSError as e:
            logger.warning("Failed to load theme file %s: %s", path, e)
        return None

    @classmethod
    def apply(cls, app: QApplication, theme_name: str) -> None:
        stylesheet = cls.THEMES.get(theme_name, cls.THEMES["dark"])
        custom_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "config", f"{theme_name}.qss"
        )
        custom = cls.load_from_file(custom_path)
        if custom:
            stylesheet = custom
        app.setStyleSheet(stylesheet)
