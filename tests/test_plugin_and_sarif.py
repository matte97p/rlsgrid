"""Tests for the pytest plugin wiring and SARIF output — no DB required."""

from __future__ import annotations

from rlsgrid.fuzz.chaos import Breach
from rlsgrid.pytest_plugin import RlsgridRunner
from rlsgrid.sarif import build_sarif


def test_runner_holds_config_and_tenants() -> None:
    r = RlsgridRunner("custom.toml", 7)
    assert r.config_path == "custom.toml"
    assert r.tenants == 7


def test_rlsgrid_fixture_is_registered(rlsgrid: RlsgridRunner) -> None:
    # The plugin's fixture resolves with the default option values.
    assert isinstance(rlsgrid, RlsgridRunner)
    assert rlsgrid.tenants == 3
    assert rlsgrid.config_path == "rlsgrid.toml"


def test_sarif_empty_is_valid() -> None:
    doc = build_sarif([], version="0.5.0")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "rlsgrid"
    assert doc["runs"][0]["results"] == []


def test_sarif_maps_breach_to_result() -> None:
    b = Breach("authenticated", "A", "B", "public", "docs", "UPDATE", "1 row updated")
    doc = build_sarif([b], version="0.5.0")
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "cross-tenant-leak"
    assert result["level"] == "error"
    assert "public.docs" in result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "public/docs"
