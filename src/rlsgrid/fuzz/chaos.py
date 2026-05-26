"""Cross-tenant chaos fuzz.

Picks pairs of seeded tenants (actor, target) and probes whether the actor
can READ, INSERT INTO, UPDATE, or DELETE the target's data. Every successful
cross-tenant op is reported as a Breach with full context.

Two modes are supported:

- **jwt**: the classic Supabase pattern. The probe SETs LOCAL ROLE plus JWT
  claims for the actor and exercises the policy on a table where the target
  owns rows.
- **function**: an access helper (e.g. `check_user_has_access_to_store`)
  decides authorisation. The probe calls that function with actor + target
  args and asserts it returns false.

Both modes wrap every probe in a transaction that is rolled back even on
success, so the database state never moves between iterations.
"""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import psycopg

from ..config import Config, TenancyConfig
from ..fixtures import SeededRow, SeededTenant
from ..introspect import IntrospectionResult
from ..matrix import Expected, MatrixCell, build_matrix
from ..synth import synth_value


@dataclass(frozen=True)
class Breach:
    actor_role: str
    actor_tenant: str
    target_tenant: str
    schema: str
    table: str
    operation: str
    detail: str


@dataclass
class FuzzReport:
    iterations: int
    breaches: list[Breach] = field(default_factory=list)
    skipped: int = 0

    @property
    def ok(self) -> bool:
        return not self.breaches


def run(
    introspection: IntrospectionResult,
    config: Config,
    seeded_tenants: list[SeededTenant],
) -> FuzzReport:
    if len(seeded_tenants) < 2:
        raise ValueError(f"fuzz needs at least 2 seeded tenants; got {len(seeded_tenants)}")

    if config.tenancy.mode == "function":
        return _run_function_mode(introspection, config, seeded_tenants)
    return _run_jwt_mode(introspection, config, seeded_tenants)


def _run_jwt_mode(
    introspection: IntrospectionResult,
    config: Config,
    seeded_tenants: list[SeededTenant],
) -> FuzzReport:
    rng = random.Random(config.fuzz.seed)
    cells = build_matrix(introspection, config)
    candidates = [c for c in cells if c.expected in (Expected.CONDITIONAL, Expected.ALLOW)]
    candidates = [c for c in candidates if not _is_bypass(c.role)]
    if not candidates:
        return FuzzReport(iterations=0)

    report = FuzzReport(iterations=config.fuzz.iterations)
    with psycopg.connect(config.connection.url) as conn:
        for _ in range(config.fuzz.iterations):
            cell = rng.choice(candidates)
            actor, target = rng.sample(seeded_tenants, 2)
            outcome = _probe_jwt(conn, cell, actor, target, config, introspection)
            if isinstance(outcome, Breach):
                report.breaches.append(outcome)
                if config.fuzz.stop_on_first_breach:
                    break
            elif outcome is _SKIPPED:
                report.skipped += 1
    return report


def _run_function_mode(
    introspection: IntrospectionResult,
    config: Config,
    seeded_tenants: list[SeededTenant],
) -> FuzzReport:
    if not config.tenancy.access_function:
        raise ValueError("function mode requires tenancy.access_function in config")

    report = FuzzReport(iterations=0)
    with psycopg.connect(config.connection.url) as conn:
        for actor in seeded_tenants:
            for target in seeded_tenants:
                if actor is target:
                    continue
                for row in _all_rows(target):
                    report.iterations += 1
                    outcome = _probe_function(conn, config, actor, target, row)
                    if isinstance(outcome, Breach):
                        report.breaches.append(outcome)
                        if config.fuzz.stop_on_first_breach:
                            return report
                    elif outcome is _SKIPPED:
                        report.skipped += 1
    return report


_SKIPPED = object()


def _probe_jwt(
    conn: psycopg.Connection,
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    config: Config,
    introspection: IntrospectionResult,
) -> Breach | None | object:
    qualified = f'"{cell.schema}"."{cell.table}"'
    tenant_col = config.tenancy.tenant_column
    target_rows = target.rows(cell.schema, cell.table)

    if cell.operation in ("UPDATE", "DELETE") and not target_rows:
        return _SKIPPED

    try:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(f'SET LOCAL ROLE "{cell.role}"')
            _set_jwt_claims(cur, config.tenancy, actor)
            if cell.operation == "SELECT":
                return _do_select(cur, cell, actor, target, qualified, tenant_col)
            if cell.operation == "INSERT":
                return _do_insert(cur, cell, actor, target, qualified, tenant_col, introspection)
            if cell.operation == "UPDATE":
                return _do_update(cur, cell, actor, target, target_rows[0], qualified)
            if cell.operation == "DELETE":
                return _do_delete(cur, cell, actor, target, target_rows[0], qualified)
            return None
    except psycopg.errors.InsufficientPrivilege:
        return None
    except psycopg.Error:
        return _SKIPPED
    finally:
        conn.rollback()


def _do_select(
    cur: psycopg.Cursor,
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    qualified: str,
    tenant_col: str,
) -> Breach | None:
    cur.execute(f'SELECT count(*) FROM {qualified} WHERE "{tenant_col}" = %s', (target.tenant_id,))
    leaked = int(cur.fetchone()[0])
    if leaked > 0:
        return _breach(cell, actor, target, f"{leaked} rows visible across tenants")
    return None


def _do_insert(
    cur: psycopg.Cursor,
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    qualified: str,
    tenant_col: str,
    introspection: IntrospectionResult,
) -> Breach | None | object:
    """INSERT a row stamped with target.tenant_id, filling every required col.

    A probe that violates a NOT NULL on some unrelated column would always
    raise `23502` and be marked SKIPPED — a false-negative we cannot accept.
    So we introspect the column list and synthesize values for everything
    the row needs.
    """
    columns = introspection.columns_of(cell.schema, cell.table)
    insert_cols: list[str] = []
    insert_vals: list[object] = []
    for column in columns:
        if column.name == tenant_col:
            insert_cols.append(column.name)
            insert_vals.append(target.tenant_id)
            continue
        if column.has_default or column.nullable:
            continue
        enum_labels = introspection.labels_for_enum(column.type_name)
        insert_cols.append(column.name)
        insert_vals.append(synth_value(column.type_name, enum_labels=enum_labels))

    if not insert_cols:
        return _SKIPPED

    cols_sql = ", ".join(f'"{c}"' for c in insert_cols)
    placeholders = ", ".join(["%s"] * len(insert_vals))
    cur.execute(
        f"INSERT INTO {qualified} ({cols_sql}) VALUES ({placeholders}) ON CONFLICT DO NOTHING",
        insert_vals,
    )
    if cur.rowcount and cur.rowcount > 0:
        return _breach(cell, actor, target, "row inserted with target tenant id")
    return None


def _do_update(
    cur: psycopg.Cursor,
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    row: SeededRow,
    qualified: str,
) -> Breach | None | object:
    """UPDATE the target's row by PK with a no-op self-assignment.

    `SET <pk> = <pk>` is a write at the RLS layer (so the policy fires) but
    leaves the value untouched in case the surrounding transaction does not
    end up rolling back.
    """
    if not row.pk_columns:
        return _SKIPPED
    set_clause = ", ".join(f'"{c}" = "{c}"' for c in row.pk_columns)
    where = " AND ".join(f'"{c}" = %s' for c in row.pk_columns)
    values = [row.pk_value(c) for c in row.pk_columns]
    cur.execute(
        f"UPDATE {qualified} SET {set_clause} WHERE {where}",
        values,
    )
    if cur.rowcount and cur.rowcount > 0:
        return _breach(cell, actor, target, f"{cur.rowcount} row(s) updated across tenants")
    return None


def _do_delete(
    cur: psycopg.Cursor,
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    row: SeededRow,
    qualified: str,
) -> Breach | None | object:
    if not row.pk_columns:
        return _SKIPPED
    where = " AND ".join(f'"{c}" = %s' for c in row.pk_columns)
    values = [row.pk_value(c) for c in row.pk_columns]
    cur.execute(f"DELETE FROM {qualified} WHERE {where}", values)
    if cur.rowcount and cur.rowcount > 0:
        return _breach(cell, actor, target, f"{cur.rowcount} row(s) deleted across tenants")
    return None


_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}")


def _resolve_placeholders(
    template: str,
    *,
    actor: SeededTenant,
    target: SeededTenant,
    row: SeededRow,
) -> tuple[str, list[object]] | None:
    """Substitute `{name}` placeholders with positional `%s` markers.

    Supported names:
      - `user_id`         → actor.user_id
      - `tenant_id`       → actor.tenant_id
      - `target_user_id`  → target.user_id
      - `target_tenant_id`→ target.tenant_id
      - `row_id`          → first PK column of target row
      - `row.<column>`    → arbitrary column from target row

    Returns (sql_fragment, values) or None if a placeholder cannot be
    resolved (e.g. row lacks a referenced column).
    """
    names = _PLACEHOLDER_RE.findall(template)
    values: list[object] = []
    for name in names:
        if name == "user_id":
            values.append(actor.user_id)
        elif name == "tenant_id":
            values.append(actor.tenant_id)
        elif name == "target_user_id":
            values.append(target.user_id)
        elif name == "target_tenant_id":
            values.append(target.tenant_id)
        elif name == "row_id":
            if not row.pk_columns:
                return None
            v = row.pk_value(row.pk_columns[0])
            if v is None:
                return None
            values.append(v)
        elif name.startswith("row."):
            col = name[4:]
            v = row.full_row.get(col)
            if v is None:
                return None
            values.append(v)
        else:
            return None
    return _PLACEHOLDER_RE.sub("%s", template), values


def _probe_function(
    conn: psycopg.Connection,
    config: Config,
    actor: SeededTenant,
    target: SeededTenant,
    row: SeededRow,
) -> Breach | None | object:
    """Call the configured access_function with (actor, target_row) and assert false.

    The access_function expression in rlsgrid.toml uses `{name}` placeholders
    (see _resolve_placeholders). Multi-arg signatures are supported, e.g.
    `has_access({user_id}, {row_id}, 'view')` or
    `permits({user_id}, {row.account_id}, {row.store_id})`.
    """
    template = config.tenancy.access_function or ""
    resolved = _resolve_placeholders(template, actor=actor, target=target, row=row)
    if resolved is None:
        return _SKIPPED
    sql_fragment, values = resolved

    try:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(f"SELECT {sql_fragment}", values)
            result = cur.fetchone()
            allowed = bool(result and result[0])
    except psycopg.Error:
        return _SKIPPED
    finally:
        conn.rollback()

    if allowed:
        return Breach(
            actor_role="(function-mode)",
            actor_tenant=actor.tenant_id,
            target_tenant=target.tenant_id,
            schema=row.schema,
            table=row.table,
            operation="ACCESS_FUNCTION",
            detail=f"access function returned true for cross-tenant call on row {row.pk_columns}",
        )
    return None


def _all_rows(tenant: SeededTenant) -> Iterable[SeededRow]:
    for rows in tenant.rows_by_table.values():
        yield from rows


def _breach(
    cell: MatrixCell,
    actor: SeededTenant,
    target: SeededTenant,
    detail: str,
) -> Breach:
    return Breach(
        actor_role=cell.role,
        actor_tenant=actor.tenant_id,
        target_tenant=target.tenant_id,
        schema=cell.schema,
        table=cell.table,
        operation=cell.operation,
        detail=detail,
    )


_BYPASS_ROLES = {"service_role", "postgres", "supabase_admin"}


def _is_bypass(role: str) -> bool:
    return role in _BYPASS_ROLES


def _set_jwt_claims(
    cur: psycopg.Cursor,
    tenancy: TenancyConfig,
    actor: SeededTenant,
) -> None:
    """Render the JWT claim templates and write them onto the session GUC.

    `jwt_shape = "json"` (Supabase v2) sets `request.jwt.claims` to a
    single JSON object, which is what `auth.jwt()` reads. The legacy
    "individual" shape sets one GUC per claim, which old PostgREST
    deployments expect.
    """
    rendered = {
        name: template.format(user_id=actor.user_id, tenant_id=actor.tenant_id)
        for name, template in tenancy.jwt_claims.items()
    }
    if tenancy.jwt_shape == "json":
        cur.execute(
            "SELECT set_config('request.jwt.claims', %s, true)",
            (json.dumps(rendered),),
        )
        return
    for name, value in rendered.items():
        cur.execute(
            "SELECT set_config(%s, %s, true)",
            (f"request.jwt.claim.{name}", value),
        )
