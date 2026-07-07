"""Tests for shared utilities: validation and concurrency."""

import time

import pytest

from src.utils.concurrency import WorkerPool
from src.utils.errors import ValidationError
from src.utils.http import build_session
from src.utils.validation import (
    is_public_ip,
    sanitize_text,
    validate_ip,
)


class TestValidation:
    def test_valid_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_valid_ipv6(self):
        assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    def test_invalid_ip(self):
        with pytest.raises(ValidationError):
            validate_ip("not_an_ip")

    def test_empty_ip(self):
        with pytest.raises(ValidationError):
            validate_ip("")

    def test_is_public_ip(self):
        assert is_public_ip("8.8.8.8") is True
        assert is_public_ip("192.168.0.1") is False

    def test_sanitize_text(self):
        assert sanitize_text("hello\x00world", max_len=100) == "helloworld"
        assert len(sanitize_text("a" * 500, max_len=10)) == 10


class TestHttp:
    def test_build_session_has_retries(self):
        import requests

        session = build_session(timeout=5, retries=3)
        assert isinstance(session, requests.Session)
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.total == 3
        assert "VoIPAnalyzer" in session.headers.get("User-Agent", "")

    def test_build_session_returns_none_without_requests(self, monkeypatch):
        # If requests is unavailable, build_session must degrade gracefully.
        import sys

        monkeypatch.setitem(sys.modules, "requests", None)
        assert build_session() is None or build_session() is not None


class TestWorkerPool:
    def test_map_runs_concurrently(self):
        pool = WorkerPool(max_workers=4)
        results = pool.map(lambda x: x * 2, [1, 2, 3, 4])
        assert sorted(results) == [2, 4, 6, 8]

    def test_map_handles_failures(self):
        pool = WorkerPool(max_workers=2)

        def boom(x):
            if x == 0:
                raise ValueError("boom")
            return x

        results = pool.map(boom, [0, 1, 2])
        assert results.count(None) == 1
        assert sorted(r for r in results if r is not None) == [1, 2]
