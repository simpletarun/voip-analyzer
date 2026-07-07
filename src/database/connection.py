import logging
import os
import sqlite3
import threading

from src import __db_schema_version__

logger = logging.getLogger(__name__)


class DatabaseConnection:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self.conn: sqlite3.Connection | None = None
        self._init()

    def _init(self) -> None:
        try:
            parent = os.path.dirname(self.path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self._configure_pragmas()
            self._migrate()
            logger.info("Database opened: %s", self.path)
        except sqlite3.Error as e:
            logger.critical("DB init failed: %s", e)
            self.conn = None

    def _configure_pragmas(self) -> None:
        if not self.conn:
            return
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA cache_size=-8000")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error as e:
            logger.warning("PRAGMA config failed: %s", e)

    def _migrate(self) -> None:
        if not self.conn:
            return
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, duration_seconds REAL,
                total_packets INTEGER, total_bytes INTEGER,
                p2p_count INTEGER, relay_count INTEGER, unknown_count INTEGER,
                countries TEXT, protocol TEXT, notes TEXT
            );
            CREATE TABLE IF NOT EXISTS peers (
                ip TEXT PRIMARY KEY, isp TEXT, org TEXT, city TEXT,
                country TEXT, lat REAL, lon REAL, asn TEXT,
                classification TEXT, confidence REAL,
                first_seen TEXT, last_seen TEXT,
                packet_count INTEGER DEFAULT 0, byte_count INTEGER DEFAULT 0,
                is_favorite INTEGER DEFAULT 0, notes TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY, data_json TEXT,
                cached_at TEXT, expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE INDEX IF NOT EXISTS idx_sessions_ts ON sessions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_peers_country ON peers(country);
            CREATE INDEX IF NOT EXISTS idx_peers_isp ON peers(isp);
            CREATE INDEX IF NOT EXISTS idx_peers_classification ON peers(classification);
            CREATE INDEX IF NOT EXISTS idx_peers_ip ON peers(ip);
            CREATE INDEX IF NOT EXISTS idx_cache_expires ON ip_cache(expires_at);
            CREATE INDEX IF NOT EXISTS idx_cache_ip ON ip_cache(ip);
        """)
        cur.execute("SELECT COUNT(*) FROM schema_version")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO schema_version (version) VALUES (?)",
                        (__db_schema_version__,))
        self._add_column_if_missing("peers", "session_id",
            "INTEGER REFERENCES sessions(id) ON DELETE CASCADE")
        self._ensure_index("peers", "idx_peers_session", "session_id")
        self.conn.commit()

    def _add_column_if_missing(self, table: str, column: str, definition: str) -> None:
        if not self.conn:
            return
        try:
            cur = self.conn.execute(
                f"SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name='{column}'")
            if cur.fetchone()[0] == 0:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                logger.info("Added column %s.%s", table, column)
        except Exception as e:
            logger.debug("Column check failed: %s", e)

    def _ensure_index(self, table: str, index: str, column: str) -> None:
        if not self.conn:
            return
        try:
            self.conn.execute(f"CREATE INDEX IF NOT EXISTS {index} ON {table}({column})")
        except Exception as e:
            logger.debug("Index create failed: %s", e)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        if not self.conn:
            raise sqlite3.Error("Database not connected")
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, params_list: list) -> sqlite3.Cursor:
        if not self.conn:
            raise sqlite3.Error("Database not connected")
        return self.conn.executemany(sql, params_list)

    def commit(self) -> None:
        if self.conn:
            try:
                self.conn.commit()
            except sqlite3.Error as e:
                logger.error("Commit failed: %s", e)

    def vacuum(self) -> None:
        if self.conn:
            try:
                self.conn.execute("VACUUM")
            except sqlite3.Error as e:
                logger.error("Vacuum failed: %s", e)

    def backup(self, dest: str) -> bool:
        """Create a safe copy of the live database (hot backup)."""
        if not self.conn:
            return False
        try:
            import shutil

            parent = os.path.dirname(dest)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                shutil.copyfile(self.path, dest)
            finally:
                self.conn.execute("COMMIT")
            logger.info("Database backup written: %s", dest)
            return True
        except (sqlite3.Error, OSError) as e:
            logger.error("Backup failed: %s", e)
            return False

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
                logger.info("Database closed")
            except sqlite3.Error as e:
                logger.error("Close failed: %s", e)
            finally:
                self.conn = None

    @property
    def is_healthy(self) -> bool:
        if not self.conn:
            return False
        try:
            self.conn.execute("SELECT 1")
            return True
        except sqlite3.Error:
            return False
