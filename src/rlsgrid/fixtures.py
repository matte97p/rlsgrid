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
    return teardown_state(state, config)


def teardown_state(
    state: dict,
    config: Config,
) -> TeardownReport:
    """Delete seeded rows given an in-memory state dict (see SeedReport.to_state).

    Rows are removed by their seeded primary keys — this works for the tenant
    root table (which has no tenant column) as well as children, and never
    touches rows the seeder did not create. Tables are processed in reverse
    seeding order (children before parents) so foreign keys do not block the
    delete; any residual FK failures are retried across a few passes.
    """
    # Collect rows per table, preserving first-seen (seeding) order.
    rows_by_table: dict[str, list[dict]] = {}
    for tenant in state.get("tenants", []):
        for qualified, rows in tenant["rows_per_table"].items():
            rows_by_table.setdefault(qualified, []).extend(rows)

    report = TeardownReport()
    if not rows_by_table:
        return report

    # Reverse seeding order ⇒ children first.
    order = list(reversed(rows_by_table.keys()))
    with psycopg.connect(config.connection.url) as conn:
        conn.autocommit = True
        pending = order
        for _pass in range(3):
            still_failing: list[str] = []
            for qualified in pending:
                rows = rows_by_table[qualified]
                if not rows:
                    continue
                ok, deleted, err = _delete_rows_by_pk(conn, qualified, rows)
                if ok:
                    report.deleted[qualified] = deleted
                    report.errors.pop(qualified, None)
                else:
                    report.errors[qualified] = err or "unknown error"
                    still_failing.append(qualified)
            if not still_failing:
                break
            pending = still_failing
    return report


def _delete_rows_by_pk(
    conn: psycopg.Connection,
    qualified: str,
    rows: list[dict],
) -> tuple[bool, int, str | None]:
    schema, _, name = qualified.partition(".")
    pk_cols = list(rows[0].keys())
    if not pk_cols:
        return True, 0, None
    table = f'"{schema}"."{name}"'

    if len(pk_cols) == 1:
        col = pk_cols[0]
        values = [r[col] for r in rows]
        sql = f'DELETE FROM {table} WHERE "{col}" = ANY(%s)'
        params: list = [values]
    else:
        cond = " OR ".join(
            "(" + " AND ".join(f'"{c}" = %s' for c in pk_cols) + ")" for _ in rows
        )
        params = [r[c] for r in rows for c in pk_cols]
        sql = f"DELETE FROM {table} WHERE {cond}"

    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return True, cur.rowcount or 0, None
    except psycopg.Error as exc:
        return False, 0, f"{type(exc).__name__}: {exc}".splitlines()[0][:200]


def seed_tenants(
    introspection: IntrospectionResult,
    config: Config,
    tenants: int = 3,
) -> SeedReport:
    if tenants < 2:
        raise ValueError("seed at least 2 tenants for cross-tenant fuzz")

    tenant_column = config.tenancy.tenant_column
    user_id_column = config.tenancy.user_id_column

    # The tenant root table keys the tenant on its own PK and is referenced by
    # children through `tenant_column` (e.g. orgs.id ← projects.org_id). It does
    # not carry tenant_column itself, so it must be detected via the FK graph
    # and seeded first, otherwise every child INSERT fails its FK to the root.
    tenant_root = _detect_tenant_root(introspection, tenant_column)

    seedable_set = {
        t.qualified: t
        for t in introspection.rls_enabled_tables()
        if introspection.has_column(t.schema, t.name, tenant_column)
    }
    if tenant_root is not None:
        root_schema, root_table, _root_col = tenant_root
        root_info = next(
            (
                t
                for t in introspection.tables
                if t.schema == root_schema and t.name == root_table
            ),
            None,
        )
        if root_info is not None:
            seedable_set.setdefault(root_info.qualified, root_info)
    ordered = topological_sort(list(seedable_set.values()), introspection)

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
                    tenant_root=tenant_root,
                )
                if row is not None:
                    tenant.rows_by_table.setdefault(row.qualified_table, []).append(row)
                elif reason:
                    skip_acc.setdefault(table.qualified, reason)
            report.tenants.append(tenant)
    report.skipped = sorted(skip_acc.items())
    return report


def _detect_tenant_root(
    introspection: IntrospectionResult,
    tenant_column: str,
) -> tuple[str, str, str] | None:
    """Find the table the tenant column points at via a foreign key.

    Returns (schema, table, referenced_column) for the first FK whose
    referencing column is `tenant_column`, or None if tenant_column is a
    free-standing value (no FK — e.g. the blog example's author_id).
    """
    for fk in introspection.foreign_keys:
        if fk.column == tenant_column:
            return (fk.ref_schema, fk.ref_table, fk.ref_column)
    return None


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
    tenant_root: tuple[str, str, str] | None = None,
) -> tuple[SeededRow | None, str | None]:
    """Return (row, skip_reason). At most one of the two is non-None."""
    columns = introspection.columns_of(table.schema, table.name)
    fks_by_col = {fk.column: fk for fk in introspection.foreign_keys_of(table.schema, table.name)}
    pk = introspection.pk_of(table.schema, table.name)

    # If this is the tenant root table, the column children reference must be
    # stamped with the tenant id so child FKs resolve.
    root_col = None
    if tenant_root is not None and (table.schema, table.name) == (tenant_root[0], tenant_root[1]):
        root_col = tenant_root[2]

    insert_columns: list[str] = []
    insert_values: list[object] = []

    for column in columns:
        if root_col is not None and column.name == root_col:
            insert_columns.append(column.name)
            insert_values.append(tenant.tenant_id)
            continue
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
