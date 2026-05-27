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
from .synth import satisfy_check, synth_value


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


@dataclass
class SeedPlan:
    ordered_tables: list[TableInfo]
    tenant_root: tuple[str, str, str] | None
    tenant_column: str


def build_seed_plan(
    introspection: IntrospectionResult,
    config: Config,
) -> SeedPlan:
    """Compute which tables get seeded and in what order — no DB writes.

    Powers `seed --dry-run` and is reused by `seed_tenants`.
    """
    tenant_column = config.tenancy.tenant_column
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
    return SeedPlan(ordered_tables=ordered, tenant_root=tenant_root, tenant_column=tenant_column)


def seed_tenants(
    introspection: IntrospectionResult,
    config: Config,
    tenants: int = 3,
) -> SeedReport:
    if tenants < 2:
        raise ValueError("seed at least 2 tenants for cross-tenant fuzz")

    user_id_column = config.tenancy.user_id_column
    plan = build_seed_plan(introspection, config)
    tenant_column = plan.tenant_column
    tenant_root = plan.tenant_root
    ordered = plan.ordered_tables

    report = SeedReport(tenant_column=tenant_column)
    report.check_warnings = [
        t.qualified for t in ordered if introspection.has_check_constraints(t.schema, t.name)
    ]

    seedable_qualified = {t.qualified for t in ordered}
    skip_acc: dict[str, str] = {}
    with psycopg.connect(config.connection.url) as conn:
        conn.autocommit = True
        for _ in range(tenants):
            tenant = SeededTenant(tenant_id=str(uuid.uuid4()), user_id=str(uuid.uuid4()))
            external_refs: dict[tuple[str, str], tuple[str, object]] = {}
            for table in ordered:
                row, reason = _insert_row(
                    conn,
                    table=table,
                    introspection=introspection,
                    tenant=tenant,
                    tenant_column=tenant_column,
                    user_id_column=user_id_column,
                    tenant_root=tenant_root,
                    seedable_qualified=seedable_qualified,
                    external_refs=external_refs,
                )
                if row is not None:
                    tenant.rows_by_table.setdefault(row.qualified_table, []).append(row)
                elif reason:
                    skip_acc.setdefault(table.qualified, reason)
            # Record on-demand external rows (e.g. auth.users) so teardown
            # removes them too. They are parents, so they land before their
            # children only in value; teardown deletes children-first by
            # reverse insertion order.
            for (rs, rt), (rcol, rval) in external_refs.items():
                tenant.rows_by_table.setdefault(f"{rs}.{rt}", []).append(
                    SeededRow(schema=rs, table=rt, pk_columns=(rcol,), full_row={rcol: rval})
                )
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


def _pregenerate_self_reference(
    table: TableInfo,
    columns: list[ColumnInfo],
    fks_by_col: dict[str, ForeignKeyInfo],
    pk: tuple[str, ...],
) -> dict[str, object]:
    """Pre-generate a PK value shared by self-referential FK columns.

    Only handles the common case: a single-column uuid primary key with one
    or more NOT NULL foreign keys that reference the same table. The row is
    made to point at itself. Returns {} when the pattern does not apply.
    """
    self_fks = [
        fk.column
        for fk in fks_by_col.values()
        if (fk.ref_schema, fk.ref_table) == (table.schema, table.name)
    ]
    if not self_fks or len(pk) != 1:
        return {}
    pk_col = pk[0]
    pk_type = next((c.type_name for c in columns if c.name == pk_col), "")
    if "uuid" not in (pk_type or "").lower():
        return {}
    value = str(uuid.uuid4())
    out: dict[str, object] = {pk_col: value}
    for col in self_fks:
        out[col] = value
    return out


def _insert_row(
    conn: psycopg.Connection,
    *,
    table: TableInfo,
    introspection: IntrospectionResult,
    tenant: SeededTenant,
    tenant_column: str,
    user_id_column: str,
    tenant_root: tuple[str, str, str] | None = None,
    seedable_qualified: set[str] | None = None,
    external_refs: dict[tuple[str, str], object] | None = None,
) -> tuple[SeededRow | None, str | None]:
    """Return (row, skip_reason). At most one of the two is non-None."""
    columns = introspection.columns_of(table.schema, table.name)
    fks_by_col = {fk.column: fk for fk in introspection.foreign_keys_of(table.schema, table.name)}
    pk = introspection.pk_of(table.schema, table.name)
    seedable_qualified = seedable_qualified if seedable_qualified is not None else set()
    external_refs = external_refs if external_refs is not None else {}

    # If this is the tenant root table, the column children reference must be
    # stamped with the tenant id so child FKs resolve.
    root_col = None
    if tenant_root is not None and (table.schema, table.name) == (tenant_root[0], tenant_root[1]):
        root_col = tenant_root[2]

    # Self-referential FK (e.g. nodes.parent_id → nodes.id): if the PK is a
    # single uuid we can pre-generate, point the first row at itself so a
    # NOT NULL self-FK does not block seeding hierarchical tables.
    pregenerated = _pregenerate_self_reference(table, columns, fks_by_col, pk)

    insert_columns: list[str] = []
    insert_values: list[object] = []

    for column in columns:
        if column.name in pregenerated:
            insert_columns.append(column.name)
            insert_values.append(pregenerated[column.name])
            continue
        if root_col is not None and column.name == root_col:
            insert_columns.append(column.name)
            insert_values.append(tenant.tenant_id)
            continue

        # FK to a table outside the seedable set (e.g. accounts.owner_user_id →
        # auth.users): seed a minimal row in that table on demand and point at it.
        fk = fks_by_col.get(column.name)
        if (
            fk is not None
            and column.name not in (tenant_column, user_id_column)
            and f"{fk.ref_schema}.{fk.ref_table}" not in seedable_qualified
            and not tenant.rows(fk.ref_schema, fk.ref_table)
        ):
            ext = _ensure_external_ref(
                conn, introspection, fk.ref_schema, fk.ref_table, fk.ref_column, external_refs
            )
            if ext is not None:
                insert_columns.append(column.name)
                insert_values.append(ext)
                continue
            if not column.nullable:
                return None, f"unresolved external FK on column {column.name} → {fk.ref_schema}.{fk.ref_table}"
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


def _ensure_external_ref(
    conn: psycopg.Connection,
    introspection: IntrospectionResult,
    ref_schema: str,
    ref_table: str,
    ref_column: str,
    cache: dict[tuple[str, str], object],
) -> object | None:
    """Seed one minimal row in a referenced table outside the seedable set.

    Handles the common Supabase pattern where tenant tables foreign-key to
    `auth.users` (an excluded, Supabase-managed schema). The referenced table's
    columns are introspected live (they are not in the cached introspection,
    which skipped excluded schemas), a minimal row is inserted, and the value
    of `ref_column` is returned and cached so sibling FKs reuse the same row.
    """
    key = (ref_schema, ref_table)
    if key in cache:
        return cache[key][1]

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name, udt_name, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
            """,
            (ref_schema, ref_table),
        )
        cols = cur.fetchall()
    if not cols:
        return None

    insert_cols: list[str] = []
    insert_vals: list[object] = []
    ref_value: object | None = None
    for name, udt, nullable, default in cols:
        is_ref = name == ref_column
        if not is_ref and (default is not None or nullable == "YES"):
            continue
        value = _synth_unique(udt)
        if is_ref:
            ref_value = value
        insert_cols.append(name)
        insert_vals.append(value)

    if ref_value is None:
        ref_udt = next((u for n, u, _, _ in cols if n == ref_column), "uuid")
        ref_value = _synth_unique(ref_udt)
        insert_cols.append(ref_column)
        insert_vals.append(ref_value)

    cols_sql = ", ".join(f'"{c}"' for c in insert_cols)
    placeholders = ", ".join(["%s"] * len(insert_vals))
    sql = (
        f'INSERT INTO "{ref_schema}"."{ref_table}" ({cols_sql}) '
        f"VALUES ({placeholders}) ON CONFLICT DO NOTHING "
        f'RETURNING "{ref_column}"'
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql, insert_vals)
            row = cur.fetchone()
    except psycopg.Error:
        return None
    value = row[0] if row else ref_value
    cache[key] = (ref_column, value)
    return value


def _synth_unique(udt: str) -> object:
    """Like synth_value but text is uniquified to dodge UNIQUE constraints."""
    udt = (udt or "").lower()
    if "uuid" in udt:
        return str(uuid.uuid4())
    if udt in ("int2", "int4", "int8", "numeric", "float4", "float8"):
        return 0
    if udt == "bool":
        return False
    if "json" in udt:
        return "{}"
    if "time" in udt or "date" in udt:
        return None
    return f"rlsgrid-{uuid.uuid4().hex[:12]}"


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
    checked = satisfy_check(
        introspection.check_defs.get((column.schema, column.table), []), column.name
    )
    if checked is not None:
        return checked
    enum_labels = introspection.labels_for_enum(column.type_name)
    return synth_value(column.type_name, enum_labels=enum_labels)
