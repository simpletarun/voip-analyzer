"""Shared HTTP session factory with retries, backoff and connection pooling.

All outbound API calls (ip-api, enrichment plugins, geo lookups) should use
a session built here so that:
* transient errors and HTTP 429/5xx are retried with exponential backoff,
* TCP/TLS connections are pooled (keep-alive) instead of re-opened per call,
* a consistent User-Agent is sent.
"""

from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    _HAVE_REQUESTS = True
except ImportError:  # pragma: no cover - requests is a hard dependency
    _HAVE_REQUESTS = False


def build_session(
    timeout: int = 5,
    retries: int = 3,
    user_agent: str = "VoIPAnalyzer/3.2.0",
) -> Optional["requests.Session"]:
    """Return a configured ``requests.Session``, or ``None`` if requests missing."""
    if not _HAVE_REQUESTS:
        return None
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    retry = Retry(
        total=retries,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.timeout = timeout
    return session
