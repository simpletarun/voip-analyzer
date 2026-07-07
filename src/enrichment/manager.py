"""Discovery and orchestration of enrichment plugins.

Plugins live in ``src/enrichment/`` and are discovered automatically. All
``search`` calls are dispatched concurrently via :class:`WorkerPool`.
"""

import asyncio
import importlib
import logging
import os
import pkgutil
from typing import Any, Dict, Iterable, List, Optional

from src.enrichment.base import EnrichmentPlugin
from src.utils.concurrency import WorkerPool
from src.utils.errors import PluginError

logger = logging.getLogger(__name__)


class EnrichmentManager:
    def __init__(self, config: Any, max_workers: int = 6) -> None:
        self.config = config
        self._pool = WorkerPool(max_workers=max_workers)
        self.plugins: List[EnrichmentPlugin] = []
        self._discover()

    def _discover(self) -> None:
        try:
            import src.enrichment as pkg

            for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
                if mod_name in ("base", "__init__", "manager"):
                    continue
                try:
                    mod = importlib.import_module(f"src.enrichment.{mod_name}")
                    for attr in dir(mod):
                        obj = getattr(mod, attr)
                        if (
                            isinstance(obj, type)
                            and issubclass(obj, EnrichmentPlugin)
                            and obj is not EnrichmentPlugin
                        ):
                            inst = obj()
                            inst.initialize(self.config)
                            if inst.is_available():
                                self.plugins.append(inst)
                                logger.info("Loaded enrichment: %s", inst.name)
                            else:
                                logger.debug("Skipped enrichment (unavailable): %s", inst.name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Enrichment discovery failed for %s: %s", mod_name, exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("Enrichment discovery error: %s", exc)

    @property
    def available(self) -> List[str]:
        return [p.name for p in self.plugins]

    def enrich(self, ip: str) -> Dict[str, Any]:
        """Run every available plugin for ``ip`` and merge results."""
        if not self.plugins:
            return {}
        results: List[Optional[Dict[str, Any]]] = self._pool.map(
            lambda p: self._safe_search(p, ip), self.plugins
        )
        merged: Dict[str, Any] = {}
        for res in results:
            if res:
                merged.update(res)
        return merged

    @staticmethod
    def _safe_search(plugin: EnrichmentPlugin, ip: str) -> Optional[Dict[str, Any]]:
        try:
            return plugin.search(ip) or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s enrichment failed for %s: %s", plugin.name, ip, exc)
            return None

    def enrich_ips(self, ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Synchronous bulk wrapper (convenient for scripts/tests)."""
        return {ip: self.enrich(ip) for ip in ips}

    async def enrich_many(self, ips: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Async bulk enrichment.

        Each IP's plugin set is resolved off the main thread via
        ``asyncio.to_thread``, so this scales to thousands of addresses without
        blocking (the upgrade path recommended by the audit).
        """
        ip_list = list(ips)
        tasks = [asyncio.to_thread(self.enrich, ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        merged: Dict[str, Dict[str, Any]] = {}
        for ip, res in zip(ip_list, results):
            if isinstance(res, dict):
                merged[ip] = res
        return merged
