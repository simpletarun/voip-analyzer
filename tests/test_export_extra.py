"""Tests for the additional exporters (Markdown always; Excel/PDF if deps present)."""

import os
import tempfile

from src.export.markdown_exporter import MarkdownExporter
from src.models.ip_info import IPInfo
from src.models.session import SessionReport


def _peers():
    intel = IPInfo(ip="8.8.8.8", isp="Google", city="Mountain View",
                   country="US", lat=37.4, lon=-122.1, asn="AS15169",
                   confidence=0.95, classification="RELAY")
    return {"8.8.8.8": {"intel": intel,
                        "stats": {"packets": 100, "bytes": 5000,
                                  "inbound": 50, "outbound": 50},
                        "type": "RELAY"}}


def _report():
    return SessionReport(id=1, timestamp="2026-07-07T12:00:00",
                         duration_seconds=30.0, total_packets=100,
                         total_bytes=5000, p2p_count=1, relay_count=1,
                         unknown_count=0, countries=["US"], protocol="WhatsApp")


def test_markdown_export():
    tmp = tempfile.mktemp(suffix=".md")
    try:
        assert MarkdownExporter().export(_report(), _peers(), tmp)
        with open(tmp, encoding="utf-8") as f:
            content = f.read()
        assert "# VoIP Analysis Report" in content
        assert "8.8.8.8" in content
        assert "Google" in content
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def test_excel_export_if_available():
    try:
        from src.export.excel_exporter import ExcelExporter
    except ImportError:
        return
    tmp = tempfile.mktemp(suffix=".xlsx")
    try:
        assert ExcelExporter().export(_report(), _peers(), tmp)
        assert os.path.getsize(tmp) > 0
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def test_pdf_export_if_available():
    try:
        from src.export.pdf_exporter import PdfExporter
    except ImportError:
        return
    tmp = tempfile.mktemp(suffix=".pdf")
    try:
        assert PdfExporter().export(_report(), _peers(), tmp)
        assert os.path.getsize(tmp) > 0
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
