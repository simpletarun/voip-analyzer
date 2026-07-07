"""Tests for exporters."""
import json
import os
import tempfile
from src.export.csv_exporter import CsvExporter
from src.export.json_exporter import JsonExporter
from src.export.html_exporter import HtmlExporter
from src.models.session import SessionReport
from src.models.ip_info import IPInfo


def _make_peers():
    intel = IPInfo(ip="8.8.8.8", isp="Google", city="Mountain View",
                   country="US", lat=37.4, lon=-122.1, asn="AS15169",
                   confidence=0.95, classification="RELAY")
    return {
        "8.8.8.8": {
            "intel": intel,
            "stats": {"packets": 100, "bytes": 5000, "inbound": 50, "outbound": 50},
            "type": "RELAY",
        }
    }


def _make_report():
    return SessionReport(
        id=1,
        timestamp="2026-07-07T12:00:00",
        duration_seconds=30.0,
        total_packets=100,
        total_bytes=5000,
        p2p_count=1,
        relay_count=1,
        unknown_count=0,
        countries=["US"],
        protocol="WhatsApp",
    )


class TestCsvExporter:
    def test_export(self):
        tmp = tempfile.mktemp(suffix=".csv")
        try:
            result = CsvExporter().export(_make_report(), _make_peers(), tmp)
            assert result is True
            with open(tmp, "r") as f:
                content = f.read()
            assert "Session Report" in content
            assert "8.8.8.8" in content
            assert "Google" in content
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


class TestJsonExporter:
    def test_export(self):
        tmp = tempfile.mktemp(suffix=".json")
        try:
            result = JsonExporter().export(_make_report(), _make_peers(), tmp)
            assert result is True
            with open(tmp, "r") as f:
                data = json.load(f)
            assert "report" in data
            assert "peers" in data
            assert data["report"]["total_packets"] == 100
            assert "8.8.8.8" in data["peers"]
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_empty_peers(self):
        tmp = tempfile.mktemp(suffix=".json")
        try:
            result = JsonExporter().export(_make_report(), {}, tmp)
            assert result is True
            with open(tmp, "r") as f:
                data = json.load(f)
            assert data["peers"] == {}
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


class TestHtmlExporter:
    def test_export(self):
        tmp = tempfile.mktemp(suffix=".html")
        try:
            result = HtmlExporter().export(_make_report(), _make_peers(), tmp)
            assert result is True
            with open(tmp, "r", encoding="utf-8") as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "VoIP Analysis Report" in content
            assert "8.8.8.8" in content
            assert "100" in content
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_html_escaping(self):
        peers = {
            '<script>alert("xss")</script>': {
                "intel": IPInfo(
                    ip='<script>alert("xss")</script>',
                    isp='<b>bold</b>',
                    city='<i>city</i>',
                    country='<a>country</a>',
                ),
                "stats": {"packets": 1, "bytes": 100},
                "type": "RELAY",
            }
        }
        tmp = tempfile.mktemp(suffix=".html")
        try:
            result = HtmlExporter().export(_make_report(), peers, tmp)
            assert result is True
            with open(tmp, "r", encoding="utf-8") as f:
                content = f.read()
            assert "&lt;script&gt;" in content
            assert "<script>" not in content
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
