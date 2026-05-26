"""Prod-guard for write-capable commands.

The seeder and the fuzz harness both perform INSERT/UPDATE/DELETE against
the live database. If `DATABASE_URL` accidentally points at production, the
blast radius is real: synthetic tenants, rolled-back UPDATEs that fire
triggers, etc. rlsgrid refuses to run such commands when the URL matches
any pattern in `[safety].forbid_url_patterns` unless the caller sets the
escape-hatch env var (intentionally awkward to mistype).
"""

from __future__ import annotations

import os

ESCAPE_HATCH = "RLSGRID_I_KNOW_WHAT_IM_DOING"


class ProdGuardViolation(RuntimeError):
    """Raised when the configured DB URL matches a forbidden pattern."""


def assert_safe_to_write(url: str, forbid_patterns: list[str]) -> None:
    matched = [p for p in forbid_patterns if p and p in url]
    if not matched:
        return
    if os.environ.get(ESCAPE_HATCH) == "1":
        return
    raise ProdGuardViolation(
        "Refusing to write to a database whose URL matches a forbidden "
        f"pattern: {matched!r}. "
        f"Set {ESCAPE_HATCH}=1 to override (only if you are absolutely sure)."
    )
