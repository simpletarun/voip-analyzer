"""Tests for the composition root (dependency injection)."""

from src.composition import AnalysisStack, build_stack


def test_build_stack_wires_repos_and_services():
    stack = build_stack(config=None, db=None)
    assert isinstance(stack, AnalysisStack)
    assert stack.session_repo is not None
    assert stack.peer_repo is not None
    assert stack.cache_repo is not None
    assert stack.enrichment is not None
    assert stack.ip_intel is not None
    # The same config object is shared across the stack (single source of truth).
    assert stack.ip_intel.config is stack.config
