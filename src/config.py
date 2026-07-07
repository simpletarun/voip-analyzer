import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

from dotenv import load_dotenv

from src import __version__

load_dotenv()


def _get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'Cutter')
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_path(path: str) -> str:
    base = _get_base_dir()
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(base, path))


@dataclass
class AppConfig:
    version: str = __version__
    debug: bool = False
    api_timeout: int = 5
    cache_ttl_hours: int = 24
    max_api_calls_per_min: int = 40
    gui_update_interval_ms: int = 100
    stats_update_interval_ms: int = 1000
    max_table_rows: int = 5000
    db_path: str = "data/voip_data.db"
    log_level: str = "INFO"
    log_max_bytes: int = 5 * 1024 * 1024
    log_backup_count: int = 3
    theme: str = "dark"
    language: str = "en"
    interface: str = ""
    data_retention_days: int = 90
    whatsapp_ports: List[Tuple[int, int]] = field(default_factory=lambda: [
        (55221, 55427), (10000, 20000), (3478, 3479),
        (4048, 4050), (5000, 5004), (8000, 9000),
        (49152, 65535), (443, 443),
    ])

    def __post_init__(self) -> None:
        self._resolve_paths()
        self._validate()

    def _resolve_paths(self) -> None:
        self.db_path = _resolve_path(self.db_path)

    def _validate(self) -> None:
        if self.api_timeout < 1:
            self.api_timeout = 5
        if self.cache_ttl_hours < 1:
            self.cache_ttl_hours = 24
        if self.max_api_calls_per_min < 1:
            self.max_api_calls_per_min = 40
        if self.gui_update_interval_ms < 16:
            self.gui_update_interval_ms = 16
        if self.max_table_rows < 100:
            self.max_table_rows = 100
        valid_themes = {"dark", "light"}
        if self.theme not in valid_themes:
            self.theme = "dark"
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level not in valid_levels:
            self.log_level = "INFO"

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AppConfig":
        cfg = cls()
        if path is None:
            path = _resolve_path("config/config.json")
            if not os.path.exists(path) and getattr(sys, 'frozen', False):
                bundled = os.path.join(os.path.dirname(sys.executable), '_internal', 'config', 'config.json')
                if os.path.exists(bundled):
                    path = bundled
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
                cfg._resolve_paths()
                cfg._validate()
            except (json.JSONDecodeError, OSError) as e:
                import logging
                logging.warning("Config load failed: %s", e)
        cfg._apply_env_overrides()
        return cfg

    def _apply_env_overrides(self) -> None:
        mappings = {
            "VOIP_DEBUG": ("debug", bool),
            "VOIP_API_TIMEOUT": ("api_timeout", int),
            "VOIP_CACHE_TTL": ("cache_ttl_hours", int),
            "VOIP_MAX_API_CALLS": ("max_api_calls_per_min", int),
            "VOIP_DB_PATH": ("db_path", str),
            "VOIP_LOG_LEVEL": ("log_level", str),
            "VOIP_THEME": ("theme", str),
            "VOIP_INTERFACE": ("interface", str),
        }
        for env_key, (attr, cast) in mappings.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    if cast is bool:
                        setattr(self, attr, val.lower() in ("1", "true", "yes"))
                    else:
                        setattr(self, attr, cast(val))
                except (ValueError, TypeError):
                    pass

    def save(self, path: Optional[str] = None) -> None:
        if path is None:
            path = _resolve_path("config/config.json")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, indent=2, default=str)
        except OSError as e:
            import logging
            logging.error("Config save failed: %s", e)
