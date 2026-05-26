"""Unit tests for fixture seeder helpers — no DB required."""

from __future__ import annotations

from rlsgrid.fixtures import topological_sort
from rlsgrid.introspect import ForeignKeyInfo, IntrospectionResult, TableInfo


def _table(name: str) -> TableInfo:
    return TableInfo(schema="public", name=name, rls_enabled=True, rls_forced=False)


def _fk(src: str, dst: str) -> ForeignKeyInfo:
    return ForeignKeyInfo(
        schema="public",
        table=src,
        column=f"{dst}_id",
        ref_schema="public",
        ref_table=dst,
        ref_column="id",
    )


def test_topological_sort_orders_parents_first() -> None:
    tables = [_table("posts"), _table("accounts"), _table("comments")]
    intro = IntrospectionResult(
        tables=tables,
        foreign_keys=[_fk("posts", "accounts"), _fk("comments", "posts")],
    )
    ordered = [t.name for t in topological_sort(tables, intro)]
    assert ordered.index("accounts") < ordered.index("posts")
    assert ordered.index("posts") < ordered.index("comments")


def test_topological_sort_breaks_cycles_gracefully() -> None:
    tables = [_table("a"), _table("b")]
    intro = IntrospectionResult(
        tables=tables,
        foreign_keys=[_fk("a", "b"), _fk("b", "a")],
    )
    ordered = topological_sort(tables, intro)
    assert {t.name for t in ordered} == {"a", "b"}


def test_topological_sort_ignores_external_fks() -> None:
    tables = [_table("posts")]
    intro = IntrospectionResult(
        tables=tables,
        foreign_keys=[_fk("posts", "auth_users_external")],
    )
    ordered = topological_sort(tables, intro)
    assert [t.name for t in ordered] == ["posts"]


def test_topological_sort_ignores_self_reference() -> None:
    tables = [_table("nodes")]
    intro = IntrospectionResult(
        tables=tables,
        foreign_keys=[
            ForeignKeyInfo(
                schema="public",
                table="nodes",
                column="parent_id",
                ref_schema="public",
                ref_table="nodes",
                ref_column="id",
            )
        ],
    )
    ordered = topological_sort(tables, intro)
    assert [t.name for t in ordered] == ["nodes"]
