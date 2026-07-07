import json
import logging
from datetime import datetime, timedelta, timezone

_UTC = timezone.utc
from typing import Dict, List, Optional

from src.database.connection import DatabaseConnection
from src.models.ip_info import IPInfo
from src.models.session import SessionReport

logger = logging.getLogger(__name__)


class SessionRepository:
    def __init__(self, db: DatabaseConnection):
        self.db = db

    def save(self, report: SessionReport) -> Optional[int]:
        try:
            cur = self.db.execute("""
                INSERT INTO sessions (timestamp, duration_seconds, total_packets,
                    total_bytes, p2p_count, relay_count, unknown_count,
                    countries, protocol, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.timestamp, report.duration_seconds, report.total_packets,
                report.total_bytes, report.p2p_count, report.relay_count,
                report.unknown_count, json.dumps(report.countries),
                report.protocol, report.notes
            ))
            self.db.commit()
            return cur.lastrowid
        except Exception as e:
            logger.error("Save session failed: %s", e)
            return None

    def get_all(self, limit: int = 50) -> List[Dict]:
        try:
            cur = self.db.execute(
                "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error("Get sessions failed: %s", e)
            return []

    def get_by_id(self, session_id: int) -> Optional[Dict]:
        try:
            cur = self.db.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error("Get session %d failed: %s", session_id, e)
            return None

    def delete_older_than(self, days: int) -> int:
        try:
            cutoff = (datetime.now(_UTC) - timedelta(days=days)).isoformat()
            cur = self.db.execute(
                "DELETE FROM sessions WHERE timestamp < ?", (cutoff,))
            self.db.commit()
            return cur.rowcount
        except Exception as e:
            logger.error("Session cleanup failed: %s", e)
            return 0


class PeerRepository:
    def __init__(self, db: DatabaseConnection):
        self.db = db

    def save(self, ip: str, intel: IPInfo, stats: Dict,
             first_seen: str, last_seen: str,
             session_id: Optional[int] = None) -> None:
        try:
            self.db.execute("""
                INSERT OR REPLACE INTO peers
                (ip, isp, org, city, country, lat, lon, asn, classification,
                 confidence, first_seen, last_seen, packet_count, byte_count,
                 session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip, intel.isp, intel.org, intel.city, intel.country,
                intel.lat, intel.lon, intel.asn, intel.classification,
                intel.confidence, first_seen, last_seen,
                stats.get("packets", 0), stats.get("bytes", 0),
                session_id
            ))
        except Exception as e:
            logger.error("Save peer %s failed: %s", ip, e)

    def get_by_session(self, session_id: int) -> List[Dict]:
        try:
            cur = self.db.execute(
                "SELECT * FROM peers WHERE session_id = ? OR session_id IS NULL ORDER BY packet_count DESC",
                (session_id,))
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.error("Get peers for session %d failed: %s", session_id, e)
            return []

    def toggle_favorite(self, ip: str) -> bool:
        try:
            cur = self.db.execute(
                "SELECT is_favorite FROM peers WHERE ip = ?", (ip,))
            row = cur.fetchone()
            if row:
                new_val = 0 if row["is_favorite"] else 1
                self.db.execute(
                    "UPDATE peers SET is_favorite = ? WHERE ip = ?",
                    (new_val, ip))
                self.db.commit()
                return bool(new_val)
        except Exception as e:
            logger.error("Toggle favorite %s failed: %s", ip, e)
        return False

    def delete_orphans(self) -> int:
        try:
            cur = self.db.execute(
                "DELETE FROM peers WHERE session_id IS NULL")
            self.db.commit()
            return cur.rowcount
        except Exception as e:
            logger.error("Orphan cleanup failed: %s", e)
            return 0


class CacheRepository:
    def __init__(self, db: DatabaseConnection):
        self.db = db

    def get(self, ip: str) -> Optional[IPInfo]:
        try:
            cur = self.db.execute(
                "SELECT data_json, expires_at FROM ip_cache WHERE ip = ?",
                (ip,))
            row = cur.fetchone()
            if not row:
                return None
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(_UTC) > expires:
                return None
            return IPInfo(**json.loads(row["data_json"]))
        except Exception:
            return None

    def set(self, ip: str, intel: IPInfo, ttl_hours: int = 24) -> None:
        try:
            now = datetime.now(_UTC)
            expires = now + timedelta(hours=ttl_hours)
            self.db.execute(
                "INSERT OR REPLACE INTO ip_cache (ip, data_json, cached_at, expires_at) VALUES (?, ?, ?, ?)",
                (ip, json.dumps(intel.to_dict()), now.isoformat(), expires.isoformat()))
        except Exception as e:
            logger.error("Cache write for %s failed: %s", ip, e)

    def cleanup(self) -> int:
        try:
            cur = self.db.execute(
                "DELETE FROM ip_cache WHERE expires_at < ?",
                (datetime.now(_UTC).isoformat(),))
            self.db.commit()
            return cur.rowcount
        except Exception:
            return 0
