"""Unit tests for the prod-guard."""

from __future__ import annotations

import pytest

from rlsgrid.safety import ESCAPE_HATCH, ProdGuardViolation, assert_safe_to_write


def test_allow_when_no_patterns() -> None:
    assert_safe_to_write("postgresql://localhost/anything", [])


def test_allow_when_no_pattern_matches() -> None:
    assert_safe_to_write("postgresql://stg.example/app", ["prod", "production"])


def test_refuse_when_pattern_matches() -> None:
    with pytest.raises(ProdGuardViolation) as exc:
        assert_safe_to_write("postgresql://prod.example/app", ["prod"])
    assert "prod" in str(exc.value)


def test_escape_hatch_overrides_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ESCAPE_HATCH, "1")
    assert_safe_to_write("postgresql://prod.example/app", ["prod"])


def test_escape_hatch_only_when_set_to_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ESCAPE_HATCH, "true")
    with pytest.raises(ProdGuardViolation):
        assert_safe_to_write("postgresql://prod.example/app", ["prod"])
