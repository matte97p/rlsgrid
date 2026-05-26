"""Unit tests for the function-mode placeholder resolver."""

from __future__ import annotations

from rlsgrid.fixtures import SeededRow, SeededTenant
from rlsgrid.fuzz.chaos import _resolve_placeholders


def _actor() -> SeededTenant:
    return SeededTenant(tenant_id="a-tenant", user_id="a-user")


def _target() -> SeededTenant:
    return SeededTenant(tenant_id="b-tenant", user_id="b-user")


def _row() -> SeededRow:
    return SeededRow(
        schema="public",
        table="stores",
        pk_columns=("id",),
        full_row={"id": "store-1", "account_id": "b-account"},
    )


def test_simple_two_arg_template() -> None:
    sql, values = _resolve_placeholders(
        "check_access({user_id}, {row_id})",
        actor=_actor(),
        target=_target(),
        row=_row(),
    )
    assert sql == "check_access(%s, %s)"
    assert values == ["a-user", "store-1"]


def test_multi_arg_with_row_column_lookup() -> None:
    sql, values = _resolve_placeholders(
        "has_access({user_id}, {row.account_id}, 'view')",
        actor=_actor(),
        target=_target(),
        row=_row(),
    )
    assert sql == "has_access(%s, %s, 'view')"
    assert values == ["a-user", "b-account"]


def test_target_tenant_placeholder() -> None:
    sql, values = _resolve_placeholders(
        "leaks_to({user_id}, {target_tenant_id})",
        actor=_actor(),
        target=_target(),
        row=_row(),
    )
    assert sql == "leaks_to(%s, %s)"
    assert values == ["a-user", "b-tenant"]


def test_unknown_placeholder_returns_none() -> None:
    result = _resolve_placeholders(
        "weird({totally_unknown_name})",
        actor=_actor(),
        target=_target(),
        row=_row(),
    )
    assert result is None


def test_missing_row_column_returns_none() -> None:
    result = _resolve_placeholders(
        "weird({row.does_not_exist})",
        actor=_actor(),
        target=_target(),
        row=_row(),
    )
    assert result is None
