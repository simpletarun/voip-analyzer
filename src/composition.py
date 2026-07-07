"""Composition root: build the service stack with dependency injection.

Instead of letting the UI instantiate databases, repositories and intelligence
services ad-hoc, everything is wired here once. Collaborators are passed in via
constructors (dependency injection), which keeps the UI thin and makes the
stack trivial to mock in tests.
"""

from typing import Optional

from src.config import AppConfig
from src.database.connection import DatabaseConnection
from src.database.repository import (
    CacheRepository,
    PeerRepository,
    SessionRepository,
)
from src.enrichment.manager import EnrichmentManager
from src.services.ip_intel import IPIntelligence


class AnalysisStack:
    def __init__(self, config: AppConfig, db: DatabaseConnection) -> None:
        self.config = config
        self.db = db
        self.session_repo = SessionRepository(db)
        self.peer_repo = PeerRepository(db)
        self.cache_repo = CacheRepository(db)
        self.enrichment = EnrichmentManager(config)
        self.ip_intel = IPIntelligence(
            self.cache_repo, config, enrichment_manager=self.enrichment
        )


def build_stack(
    config: Optional[AppConfig] = None,
    db: Optional[DatabaseConnection] = None,
) -> AnalysisStack:
    if config is None:
        config = AppConfig.load()
    if db is None:
        db = DatabaseConnection(config.db_path)
    return AnalysisStack(config, db)
