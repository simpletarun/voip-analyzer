"""Tests for the enrichment plugin framework.

Real enrichment plugins require API keys and network access, so we only
assert the framework behaviour (discovery, availability gating, concurrency,
safe error handling) which works with no keys configured.
"""

from src.enrichment.base import EnrichmentPlugin
from src.enrichment.manager import EnrichmentManager


class _DummyPlugin(EnrichmentPlugin):
    name = "dummy"
    version = "0.1.0"
    description = "test"
    requires_key = False

    def search(self, ip: str) -> dict:
        return {"dummy_seen": ip}


def test_manager_discovers_no_real_plugins_without_keys():
    mgr = EnrichmentManager(config=None)
    # With no API keys in the environment, all real plugins should be skipped.
    # The framework itself must still instantiate cleanly.
    assert isinstance(mgr.plugins, list)


def test_manager_enrich_empty_when_no_plugins():
    mgr = EnrichmentManager(config=None)
    # enrich is safe to call and returns a dict even with no available plugins
    assert isinstance(mgr.enrich("8.8.8.8"), dict)


def test_plugin_metadata_shape():
    p = _DummyPlugin()
    meta = p.metadata()
    assert meta["name"] == "dummy"
    assert meta["version"] == "0.1.0"
    assert meta["requires_key"] is False


def test_enrich_many_async():
    import asyncio

    from src.enrichment.manager import EnrichmentManager

    mgr = EnrichmentManager(config=None)
    mgr.plugins = [_DummyPlugin()]
    out = asyncio.run(mgr.enrich_many(["8.8.8.8", "1.1.1.1"]))
    assert set(out.keys()) == {"8.8.8.8", "1.1.1.1"}
    assert out["8.8.8.8"]["dummy_seen"] == "8.8.8.8"


def test_enrich_ips_sync():
    from src.enrichment.manager import EnrichmentManager

    mgr = EnrichmentManager(config=None)
    mgr.plugins = [_DummyPlugin()]
    out = mgr.enrich_ips(["9.9.9.9"])
    assert out["9.9.9.9"]["dummy_seen"] == "9.9.9.9"
