"""Bounded thread-pool helper for concurrent, independent lookups.

Replaces the previous single-threaded resolver so that multiple IP
enrichments can run in parallel (see review point 11). The pool is sized from
configuration and shuts down cleanly on context exit.
"""

import concurrent.futures
import logging
import threading
from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")

logger = logging.getLogger(__name__)


class WorkerPool:
    def __init__(self, max_workers: int = 8) -> None:
        self._max_workers = max(1, max_workers)
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._lock:
            if self._executor is None or self._executor._shutdown:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self._max_workers, thread_name_prefix="Worker"
                )
            return self._executor

    def map(self, func: Callable[[T], R], items: Iterable[T]) -> list[R]:
        """Run ``func`` over ``items`` concurrently.

        Failures are logged and yield ``None`` so one bad item does not abort
        the whole batch.
        """
        items = list(items)
        if not items:
            return []
        try:
            with self._ensure() as ex:
                futures = [ex.submit(func, item) for item in items]
                results: list[R] = []
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        results.append(fut.result())
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Worker task failed: %s", exc)
                        results.append(None)  # type: ignore[arg-type]
                return results
        except Exception as exc:  # noqa: BLE001
            logger.error("WorkerPool.map error: %s", exc)
            return []

    def shutdown(self) -> None:
        with self._lock:
            if self._executor and not self._executor._shutdown:
                self._executor.shutdown(wait=False)
