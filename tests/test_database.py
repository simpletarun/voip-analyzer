"""Tests for database repositories."""
import os
import tempfile
from datetime import datetime, timezone

import pytest

from src.database.connection import DatabaseConnection
from src.database.repository import CacheRepository, PeerRepository, SessionRepository
from src.models.ip_info import IPInfo
from src.models.session import SessionReport

_UTC = timezone.utc


@pytest.fixture
def db():
    tmp = tempfile.mktemp(suffix=".db")
    conn = DatabaseConnection(tmp)
    yield conn
    conn.close()
    try:
        os.unlink(tmp)
    except OSError:
        pass


@pytest.fixture
def session_repo(db):
    return SessionRepository(db)


@pytest.fixture
def peer_repo(db):
    return PeerRepository(db)


@pytest.fixture
def cache_repo(db):
    return CacheRepository(db)


class TestSessionRepository:
    def test_save_and_get_all(self, session_repo):
        report = SessionReport(
            timestamp=datetime.now(_UTC).isoformat(),
            duration_seconds=30.5,
            total_packets=100,
            total_bytes=5000,
            p2p_count=2,
            relay_count=3,
            unknown_count=1,
            countries=["India", "US"],
            protocol="WhatsApp",
        )
        sid = session_repo.save(report)
        assert sid is not None

        sessions = session_repo.get_all()
        assert len(sessions) >= 1
        assert sessions[0]["total_packets"] == 100

    def test_get_by_id(self, session_repo):
        report = SessionReport(
            timestamp=datetime.now(_UTC).isoformat(),
            duration_seconds=10.0,
            total_packets=50,
            total_bytes=2000,
        )
        sid = session_repo.save(report)
        assert sid is not None

        found = session_repo.get_by_id(sid)
        assert found is not None
        assert found["id"] == sid

    def test_get_by_id_missing(self, session_repo):
        assert session_repo.get_by_id(9999) is None

    def test_delete_older_than(self, session_repo):
        old = SessionReport(
            timestamp="2020-01-01T00:00:00",
            duration_seconds=1.0,
            total_packets=1,
            total_bytes=1,
        )
        session_repo.save(old)
        deleted = session_repo.delete_older_than(30)
        assert deleted >= 1


class TestPeerRepository:
    def test_save_and_get_by_session(self, db, session_repo, peer_repo):
        report = SessionReport(
            timestamp="now", duration_seconds=1.0,
            total_packets=1, total_bytes=1,
        )
        sid = session_repo.save(report)
        assert sid is not None

        intel = IPInfo(ip="8.8.8.8", isp="Google", country="US")
        stats = {"packets": 10, "bytes": 500, "inbound": 5, "outbound": 5}
        peer_repo.save("8.8.8.8", intel, stats, "now", "now", session_id=sid)

        peers = peer_repo.get_by_session(sid)
        assert len(peers) >= 1
        assert peers[0]["ip"] == "8.8.8.8"

    def test_toggle_favorite(self, peer_repo):
        intel = IPInfo(ip="4.4.4.4", isp="Test")
        stats = {"packets": 1, "bytes": 100, "inbound": 1, "outbound": 0}
        peer_repo.save("4.4.4.4", intel, stats, "now", "now")

        result = peer_repo.toggle_favorite("4.4.4.4")
        assert result is True

        result2 = peer_repo.toggle_favorite("4.4.4.4")
        assert result2 is False


class TestCacheRepository:
    def test_set_and_get(self, cache_repo):
        intel = IPInfo(ip="1.1.1.1", isp="Cloudflare", country="US",
                       lat=40.0, lon=-74.0, asn="AS13335")
        cache_repo.set("1.1.1.1", intel, ttl_hours=24)

        cached = cache_repo.get("1.1.1.1")
        assert cached is not None
        assert cached.isp == "Cloudflare"
        assert cached.asn == "AS13335"

    def test_get_missing(self, cache_repo):
        assert cache_repo.get("99.99.99.99") is None

    def test_cleanup(self, cache_repo):
        intel = IPInfo(ip="2.2.2.2", isp="Test")
        cache_repo.set("2.2.2.2", intel, ttl_hours=0)

        removed = cache_repo.cleanup()
        assert removed >= 1



