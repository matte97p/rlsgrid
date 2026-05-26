"""Schema-aware fixture seeder for multi-tenant fuzz runs.

For each synthetic tenant the seeder walks the FK graph in topological order
and inserts one row per RLS-enabled table that carries the configured
tenant column. FK columns are filled with PKs from rows already seeded for
the same tenant, which means a parent row owned by tenant A always points
at a child row owned by tenant A — the fuzz harness can then prove that
tenant B cannot reach either of them.

The seeder uses a service-role-style connection. The caller is responsible
for pointing `DATABASE_URL` at a non-production database.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .config import Config
from .introspect import ColumnInfo, ForeignKeyInfo, IntrospectionResult, TableInfo
from .synth import synth_value


@dataclass
class SeededRow:
    schema: str
    table: str
    pk_columns: tuple[str, ...]
    full_row: dict[str, object]

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"

    def pk_value(self, column: str) -> object | None:
        return self.full_row.get(column)


@dataclass
class SeededTenant:
    tenant_id: str
    user_id: str
    rows_by_table: dict[str, list[SeededRow]] = field(default_factory=dict)

    def rows(self, schema: str, table: str) -> list[SeededRow]:
        return self.rows_by_table.get(f"{schema}.{table}", [])


@dataclass
class SeedReport:
    tenants: list[SeededTenant] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (qualified_table, reason)
    check_warnings: list[str] = field(default_factory=list)  # qualified tables with CHECK constraints
    tenant_column: str = ""

    def coverage_for(self, table: TableInfo) -> int:
        return sum(len(t.rows(table.schema, table.name)) for t in self.tenants)

    def to_state(self) -> dict:
        """Serialise seeded state to a teardown- and pgTAP-friendly dict."""
        return {
            "tenant_column": self.tenant_column,
            "tenants": [
                {
                    "tenant_id": t.tenant_id,
                    "user_id": t.user_id,
                    "rows_per_table": {
                        qualified: [
                            {col: _jsonable(row.pk_value(col)) for col in row.pk_columns}
                            for row in rows
                        ]
                        for qualified, rows in t.rows_by_table.items()
                    },
                }
                for t in self.tenants
            ],
        }

    def write_state(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_state(), indent=2))


def _jsonable(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


@dataclass
class TeardownReport:
    deleted: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def total_deleted(self) -> int:
        return sum(self.deleted.values())


def teardown_from_state(
    state_path: str | Path,
    config: Config,
) -> TeardownReport:
    """DELETE rows belonging to previously seeded tenants.

    Reads the JSON state produced by `SeedReport.write_state` and removes
    every row whose tenant column matches any seeded tenant id. Tables and
    schemas are taken from the state itself, not re-introspected, so a
    teardown still works after the schema has changed.
    """
    state = json.loads(Path(state_path).read_text())
    tenant_column = state.get("tenant_column") or config.tenancy.tenant_column
    tenant_ids = [t["tenant_id"] for t in state["tenants"]]
    if not tenant_ids:
        return TeardownReport()

    qualified_tables: set[str] = set()
    for tenant in state["tenants"]:
        qualified_tables.update(tenant["rows_per_table"].keys())

    report = TeardownReport()
    with psycopg.connect(config.connection.url) as conn:
        conn.autocommit = True
        for qualified in sorted(qualified_tables):
            schema, _, name = qualified.partition(".")
            sql = f'DELETE FROM "{schema}"."{name}" WHERE "{tenant_column}" = ANY(%s)'
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, (tenant_ids,))
                    report.deleted[qualified] = cur.rowcount or 0
            except psycopg.Error as exc:
                report.errors[qualified] = f"{type(exc).__name__}: {exc}".splitlines()[0][:200]
    return report


def seed_tenants(
    introspection: IntrospectionResult,
    config: Config,
    tenants: int = 3,
) -> SeedReport:
    if tenants < 2:
        raise ValueError("seed at least 2 tenants for cross-tenant fuzz")

    tenant_column = config.tenancy.tenant_column
    user_id_column = config.tenancy.user_id_column
    seedable = [
        t
        for t in introspection.rls_enabled_tables()
        if introspection.has_column(t.schema, t.name, tenant_column)
    ]
    ordered = topological_sort(seedable, introspection)

    report = SeedReport(tenant_column=tenant_column)
    report.check_warnings = [
        t.qualified for t in ordered if introspection.has_check_constraints(t.schema, t.name)
    ]

    skip_acc: dict[str, str] = {}
    with psycopg.connect(config.connection.url) as conn:
        conn.autocommit = True
        for _ in range(tenants):
            tenant = SeededTenant(tenant_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()))
            for table in ordered:
                row, reason = _insert_row(
                    conn,
                    table=table,
                    introspection=introspection,
                    tenant=tenant,
                    tenant_column=tenant_column,
                    user_id_column=user_id_column,
                )
                if row is not None:
                    tenant.rows_by_table.setdefault(row.qualified_table, []).append(row)
                elif reason:
                    skip_acc.setdefault(table.qualified, reason)
            report.tenants.append(tenant)
    report.skipped = sorted(skip_acc.items())
    return report


def topological_sort(
    tables: list[TableInfo],
    introspection: IntrospectionResult,
) -> list[TableInfo]:
    """Kahn's algorithm over FKs restricted to the input table set.

    FKs pointing outside the set are ignored (they are filled with NULL or
    cause the row to be skipped at insert time). Cycles are broken by
    appending the remaining tables in introspection order.
    """
    by_qualified = {t.qualified: t for t in tables}
    qualified_set = set(by_qualified)
    indeg: dict[str, int] = dict.fromkeys(qualified_set, 0)
    adj: dict[str, list[str]] = {q: [] for q in qualified_set}

    for fk in introspection.foreign_keys:
        src = f"{fk.schema}.{fk.table}"
        dst = f"{fk.ref_schema}.{fk.ref_table}"
        if src == dst:
            continue
        if src in qualified_set and dst in qualified_set:
            adj[dst].append(src)
            indeg[src] += 1

    queue = [q for q, d in indeg.items() if d == 0]
    out: list[str] = []
    while queue:
        q = queue.pop(0)
        out.append(q)
        for nxt in adj[q]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)

    if len(out) != len(qualified_set):
        seen = set(out)
        for t in tables:
            if t.qualified not in seen:
                out.append(t.qualified)

    return [by_qualified[q] for q in out]


def _insert_row(
    conn: psycopg.Connection,
    *,
    table: TableInfo,
    introspection: IntrospectionResult,
    tenant: SeededTenant,
    tenant_column: str,
    user_id_column: str,
) -> tuple[SeededRow | None, str | None]:
    """Return (row, skip_reason). At most one of the two is non-None."""
    columns = introspection.columns_of(table.schema, table.name)
    fks_by_col = {fk.column: fk for fk in introspection.foreign_keys_of(table.schema, table.name)}
    pk = introspection.pk_of(table.schema, table.name)

    insert_columns: list[str] = []
    insert_values: list[object] = []

    for column in columns:
        value = _resolve_value(
            column,
            fks_by_col=fks_by_col,
            tenant=tenant,
            tenant_column=tenant_column,
            user_id_column=user_id_column,
            introspection=introspection,
        )
        if value is _SKIP:
            continue
        if value is _UNRESOLVED:
            return None, f"unresolved FK on column {column.name}"
        insert_columns.append(column.name)
        insert_values.append(value)

    if not insert_columns:
        return None, "no insertable columns"

    cols_sql = ", ".join(f'"{c}"' for c in insert_columns)
    placeholders = ", ".join(["%s"] * len(insert_values))
    sql = (
        f'INSERT INTO "{table.schema}"."{table.name}" ({cols_sql}) '
        f"VALUES ({placeholders}) "
        "ON CONFLICT DO NOTHING "
        "RETURNING *"
    )
    try:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, insert_values)
            row = cur.fetchone()
    except psycopg.Error as exc:
        sqlstate = getattr(exc, "sqlstate", None) or "?????"
        msg = str(exc).splitlines()[0][:120]
        return None, f"insert failed ({sqlstate}): {msg}"

    if row is None:
        return None, "on conflict do nothing matched"
    return (
        SeededRow(
            schema=table.schema,
            table=table.name,
            pk_columns=pk,
            full_row=dict(row),
        ),
        None,
    )


class _Sentinel:
    def __repr__(self) -> str:
        return "<sentinel>"


_SKIP = _Sentinel()
_UNRESOLVED = _Sentinel()


def _resolve_value(
    column: ColumnInfo,
    *,
    fks_by_col: dict[str, ForeignKeyInfo],
    tenant: SeededTenant,
    tenant_column: str,
    user_id_column: str,
    introspection: IntrospectionResult,
) -> object:
    if column.name == tenant_column:
        return tenant.tenant_id
    if column.name == user_id_column:
        return tenant.user_id
    if column.name in fks_by_col:
        fk = fks_by_col[column.name]
        ref_rows = tenant.rows(fk.ref_schema, fk.ref_table)
        if ref_rows:
            value = ref_rows[0].pk_value(fk.ref_column)
            if value is not None:
                return value
        if column.nullable:
            return _SKIP
        return _UNRESOLVED
    if column.has_default:
        return _SKIP
    if column.nullable:
        return _SKIP
    enum_labels = introspection.labels_for_enum(column.type_name)
    return synth_value(column.type_name, enum_labels=enum_labels)
