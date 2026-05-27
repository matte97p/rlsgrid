"""pytest plugin: run rlsgrid's cross-tenant check from your test suite.

Loaded automatically when rlsgrid is installed (pytest11 entry point). Adds a
`rlsgrid` fixture so you can gate your suite on RLS isolation:

    def test_no_cross_tenant_leaks(rlsgrid):
        report = rlsgrid.check()
        assert report.ok, [b.detail for b in report.breaches]

Point it at a config with `--rlsgrid-config path/to/rlsgrid.toml` (default
`rlsgrid.toml`) and set tenants with `--rlsgrid-tenants N`. The check seeds,
fuzzes, and tears down — nothing is left in the database. Disable the plugin
with `-p no:rlsgrid`.
"""

from __future__ import annotations

import pytest

from .config import Config
from .fixtures import seed_tenants, teardown_state
from .fuzz import chaos
from .fuzz.chaos import FuzzReport
from .introspect import introspect


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("rlsgrid")
    group.addoption(
        "--rlsgrid-config",
        action="store",
        default="rlsgrid.toml",
        help="Path to rlsgrid.toml (default: rlsgrid.toml).",
    )
    group.addoption(
        "--rlsgrid-tenants",
        action="store",
        type=int,
        default=3,
        help="Number of synthetic tenants to seed (default: 3).",
    )


class RlsgridRunner:
    """Thin handle exposed by the `rlsgrid` fixture."""

    def __init__(self, config_path: str, tenants: int) -> None:
        self.config_path = config_path
        self.tenants = tenants

    def check(self, *, tenants: int | None = None) -> FuzzReport:
        """Seed → fuzz → teardown. Returns the FuzzReport (assert `.ok`)."""
        cfg = Config.load(self.config_path)
        introspection = introspect(cfg)
        seed_report = seed_tenants(introspection, cfg, tenants=tenants or self.tenants)
        try:
            return chaos.run(introspection, cfg, seeded_tenants=seed_report.tenants)
        finally:
            teardown_state(seed_report.to_state(), cfg)


@pytest.fixture
def rlsgrid(request: pytest.FixtureRequest) -> RlsgridRunner:
    return RlsgridRunner(
        config_path=request.config.getoption("--rlsgrid-config"),
        tenants=request.config.getoption("--rlsgrid-tenants"),
    )
