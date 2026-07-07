"""Tests for AppConfig."""
import json
import os
import tempfile
from src.config import AppConfig


class TestAppConfig:
    def test_defaults(self):
        cfg = AppConfig()
        assert cfg.api_timeout == 5
        assert cfg.cache_ttl_hours == 24
        assert cfg.max_api_calls_per_min == 40
        assert cfg.theme == "dark"
        assert cfg.log_level == "INFO"

    def test_validation_clamps_values(self):
        cfg = AppConfig(api_timeout=0, cache_ttl_hours=-1, max_table_rows=10)
        assert cfg.api_timeout == 5
        assert cfg.cache_ttl_hours == 24
        assert cfg.max_table_rows == 100

    def test_load_from_file(self):
        data = {
            "api_timeout": 10,
            "theme": "light",
            "log_level": "DEBUG",
        }
        tmp = tempfile.mktemp(suffix=".json")
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            cfg = AppConfig.load(tmp)
            assert cfg.api_timeout == 10
            assert cfg.theme == "light"
            assert cfg.log_level == "DEBUG"
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_load_nonexistent_file(self):
        cfg = AppConfig.load("/nonexistent/config.json")
        assert cfg.api_timeout == 5

    def test_save_and_reload(self):
        orig = AppConfig(theme="light", api_timeout=15)
        tmp = tempfile.mktemp(suffix=".json")
        try:
            orig.save(tmp)
            loaded = AppConfig.load(tmp)
            assert loaded.theme == "light"
            assert loaded.api_timeout == 15
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_db_path_resolution(self):
        cfg = AppConfig(db_path="data/test.db")
        assert "data" in cfg.db_path and "test.db" in cfg.db_path
        assert os.path.isabs(cfg.db_path)
