"""Unit tests for matrix classification — no DB required."""

from __future__ import annotations

from rlsgrid.config import Config, ConnectionConfig, RolesConfig, TenancyConfig
from rlsgrid.introspect import IntrospectionResult, PolicyInfo, TableInfo
from rlsgrid.matrix import Expected, build_matrix


def _config() -> Config:
    return Config(
        connection=ConnectionConfig(url="postgresql://noop"),
        tenancy=TenancyConfig(),
        roles=RolesConfig(roles={"authenticated": "user", "anon": "public", "service_role": "bypass"}),
    )


def test_unrestricted_when_rls_disabled() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=False, rls_forced=False)],
    )
    cells = build_matrix(intro, _config())
    assert all(c.expected is Expected.UNRESTRICTED for c in cells)


def test_deny_when_rls_enabled_and_no_policy() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False)],
    )
    cells = build_matrix(intro, _config())
    auth_cells = [c for c in cells if c.role == "authenticated"]
    assert auth_cells
    assert all(c.expected is Expected.DENY for c in auth_cells)


def test_allow_when_policy_has_no_qual() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False)],
        policies=[
            PolicyInfo(
                schema="public",
                table="t",
                name="open_select",
                permissive=True,
                roles=("authenticated",),
                command="SELECT",
                qual=None,
                with_check=None,
            )
        ],
    )
    cells = build_matrix(intro, _config())
    select_cell = next(c for c in cells if c.role == "authenticated" and c.operation == "SELECT")
    assert select_cell.expected is Expected.ALLOW
    assert "open_select" in select_cell.applicable_policies


def test_conditional_when_policy_has_qual() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False)],
        policies=[
            PolicyInfo(
                schema="public",
                table="t",
                name="owner_select",
                permissive=True,
                roles=("authenticated",),
                command="SELECT",
                qual="user_id = auth.uid()",
                with_check=None,
            )
        ],
    )
    cells = build_matrix(intro, _config())
    select_cell = next(c for c in cells if c.role == "authenticated" and c.operation == "SELECT")
    assert select_cell.expected is Expected.CONDITIONAL


def test_service_role_bypasses_unless_forced() -> None:
    intro = IntrospectionResult(
        tables=[
            TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False),
            TableInfo(schema="public", name="forced", rls_enabled=True, rls_forced=True),
        ],
    )
    cells = build_matrix(intro, _config())
    svc_t = next(c for c in cells if c.role == "service_role" and c.table == "t" and c.operation == "SELECT")
    svc_forced = next(c for c in cells if c.role == "service_role" and c.table == "forced" and c.operation == "SELECT")
    assert svc_t.expected is Expected.UNRESTRICTED
    assert svc_forced.expected is Expected.DENY  # FORCE RLS + no matching policy


def test_write_check_only_policy_is_conditional_for_insert() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False)],
        policies=[
            PolicyInfo(
                schema="public",
                table="t",
                name="own_insert",
                permissive=True,
                roles=("authenticated",),
                command="INSERT",
                qual=None,
                with_check="user_id = auth.uid()",
            )
        ],
    )
    cells = build_matrix(intro, _config())
    insert_cell = next(c for c in cells if c.role == "authenticated" and c.operation == "INSERT")
    assert insert_cell.expected is Expected.CONDITIONAL


def test_for_all_policy_covers_every_operation() -> None:
    intro = IntrospectionResult(
        tables=[TableInfo(schema="public", name="t", rls_enabled=True, rls_forced=False)],
        policies=[
            PolicyInfo(
                schema="public",
                table="t",
                name="all_owner",
                permissive=True,
                roles=("authenticated",),
                command="ALL",
                qual="user_id = auth.uid()",
                with_check="user_id = auth.uid()",
            )
        ],
    )
    cells = [c for c in build_matrix(intro, _config()) if c.role == "authenticated"]
    assert all(c.expected is Expected.CONDITIONAL for c in cells)


