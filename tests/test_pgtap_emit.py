"""Unit tests for the pgTAP emitter, including CONDITIONAL coverage."""

from __future__ import annotations

from rlsgrid.config import TenancyConfig
from rlsgrid.emitters.pgtap import emit
from rlsgrid.matrix import Expected, MatrixCell


def _cell(role: str, op: str, expected: Expected, table: str = "posts") -> MatrixCell:
    return MatrixCell(
        role=role,
        role_purpose="test",
        schema="public",
        table=table,
        operation=op,
        expected=expected,
        applicable_policies=("owner_policy",) if expected is Expected.CONDITIONAL else (),
    )


def test_emit_allow_deny_only_when_no_state() -> None:
    cells = [
        _cell("authenticated", "SELECT", Expected.CONDITIONAL),
        _cell("anon", "SELECT", Expected.DENY),
        _cell("authenticated", "SELECT", Expected.ALLOW),
    ]
    sql = emit(cells)
    assert "BEGIN;" in sql
    assert "SELECT plan(2);" in sql  # ALLOW + DENY only
    assert "CONDITIONAL" not in sql.splitlines()[0]  # header note absent


def test_emit_includes_conditional_with_seed_state() -> None:
    cells = [_cell("authenticated", "SELECT", Expected.CONDITIONAL)]
    state = {
        "tenant_column": "author_id",
        "tenants": [
            {
                "tenant_id": "tenant-A",
                "user_id": "user-A",
                "rows_per_table": {"public.posts": [{"id": "row-A"}]},
            },
            {
                "tenant_id": "tenant-B",
                "user_id": "user-B",
                "rows_per_table": {"public.posts": [{"id": "row-B"}]},
            },
        ],
    }
    tenancy = TenancyConfig(tenant_column="author_id")
    sql = emit(cells, seed_state=state, tenancy=tenancy)
    assert 'WHERE "author_id" = \'tenant-B\'' in sql
    assert "set_config('request.jwt.claims'" in sql
    assert "user-A" in sql  # actor user id rendered into claim
    assert "SELECT plan(1);" in sql


def test_emit_conditional_insert_uses_throws_ok() -> None:
    cells = [_cell("authenticated", "INSERT", Expected.CONDITIONAL)]
    state = {
        "tenant_column": "author_id",
        "tenants": [
            {"tenant_id": "a", "user_id": "u-a", "rows_per_table": {"public.posts": [{"id": "1"}]}},
            {"tenant_id": "b", "user_id": "u-b", "rows_per_table": {"public.posts": [{"id": "2"}]}},
        ],
    }
    sql = emit(cells, seed_state=state, tenancy=TenancyConfig(tenant_column="author_id"))
    assert "throws_ok" in sql
    assert "'42501'" in sql


def test_emit_conditional_delete_skipped_when_no_target_rows() -> None:
    cells = [_cell("authenticated", "DELETE", Expected.CONDITIONAL)]
    state = {
        "tenant_column": "author_id",
        "tenants": [
            {"tenant_id": "a", "user_id": "u-a", "rows_per_table": {}},
            {"tenant_id": "b", "user_id": "u-b", "rows_per_table": {}},
        ],
    }
    sql = emit(cells, seed_state=state, tenancy=TenancyConfig(tenant_column="author_id"))
    assert "DELETE" not in sql.upper().replace("DELETED", "")  # no DELETE statement emitted
    assert "SELECT plan(0);" in sql


def test_emit_skips_conditional_for_bypass_roles() -> None:
    cells = [_cell("service_role", "SELECT", Expected.CONDITIONAL)]
    state = {
        "tenant_column": "author_id",
        "tenants": [
            {"tenant_id": "a", "user_id": "u-a", "rows_per_table": {"public.posts": [{"id": "1"}]}},
            {"tenant_id": "b", "user_id": "u-b", "rows_per_table": {"public.posts": [{"id": "2"}]}},
        ],
    }
    sql = emit(cells, seed_state=state, tenancy=TenancyConfig(tenant_column="author_id"))
    assert "service_role" not in sql
    assert "SELECT plan(0);" in sql
