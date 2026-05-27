"""Unit tests for the schema autodetection used by `init --from-db`."""

from __future__ import annotations

from rlsgrid.autodetect import detect, render_config
from rlsgrid.introspect import ColumnInfo, ForeignKeyInfo, IntrospectionResult, TableInfo


def _fk(table: str, col: str, ref_table: str, ref_col: str = "id") -> ForeignKeyInfo:
    return ForeignKeyInfo(
        schema="public",
        table=table,
        column=col,
        ref_schema="public",
        ref_table=ref_table,
        ref_column=ref_col,
    )


def _supabase_intro() -> IntrospectionResult:
    return IntrospectionResult(
        tables=[
            TableInfo(schema="public", name="orgs", rls_enabled=True, rls_forced=False),
            TableInfo(schema="public", name="projects", rls_enabled=True, rls_forced=False),
        ],
        foreign_keys=[_fk("projects", "org_id", "orgs")],
        db_roles=["anon", "authenticated", "service_role", "postgres"],
        columns=[
            ColumnInfo("public", "projects", "org_id", "uuid", False, False),
        ],
    )


def test_detects_supabase_and_tenant_column() -> None:
    d = detect(_supabase_intro())
    assert d.is_supabase is True
    assert d.tenant_column == "org_id"
    assert d.tenant_root == ("public", "orgs", "id")
    assert "auth" in d.exclude_schemas
    assert set(d.roles) == {"authenticated", "anon", "service_role"}


def test_hint_column_preferred_as_fk() -> None:
    intro = IntrospectionResult(
        foreign_keys=[_fk("t", "some_other_id", "other"), _fk("t", "tenant_id", "tenants")],
        db_roles=[],
    )
    # tenant_id is a hint and is an FK → wins over some_other_id
    assert detect(intro).tenant_column == "tenant_id"


def test_plain_postgres_not_supabase() -> None:
    intro = IntrospectionResult(
        foreign_keys=[_fk("t", "account_id", "accounts")],
        db_roles=["app_user", "postgres"],
    )
    d = detect(intro)
    assert d.is_supabase is False
    assert d.tenant_column == "account_id"
    assert "auth" not in d.exclude_schemas


def test_fallback_tenant_column_when_nothing_matches() -> None:
    intro = IntrospectionResult(foreign_keys=[], db_roles=[], columns=[])
    assert detect(intro).tenant_column == "tenant_id"


def test_render_config_roundtrips_through_loader(tmp_path, monkeypatch) -> None:
    from rlsgrid.config import Config

    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/x")
    d = detect(_supabase_intro())
    text = render_config(d)
    cfg_path = tmp_path / "rlsgrid.toml"
    cfg_path.write_text(text)
    cfg = Config.load(cfg_path)
    assert cfg.tenancy.tenant_column == "org_id"
    assert cfg.tenancy.jwt_shape == "json"
    assert "auth" in cfg.exclude.schemas
