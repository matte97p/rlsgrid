"""Emit a pgTAP test suite from a matrix.

The emitted SQL file is meant to be run with `pg_prove` or the `pgxn` runner
inside the same database (or a freshly seeded clone). Each test wraps a single
matrix cell so a failure points to one role/table/op tuple.

ALLOW and DENY cells turn into assertions that exercise the policy without
touching real rows (probe statements use `LIMIT 0` / `WHERE false`).

CONDITIONAL cells are only emitted when the caller provides `seed_state`
from a prior `rlsgrid seed --state-out` run. The script then asserts the
true cross-tenant property: actor session must not see, write, update, or
delete the target tenant's rows.
"""

from __future__ import annotations

import json
from collections import defaultdict
from io import StringIO
from typing import Any

from ..config import TenancyConfig
from ..matrix import Expected, MatrixCell


def emit(
    cells: list[MatrixCell],
    *,
    header_note: str | None = None,
    seed_state: dict[str, Any] | None = None,
    tenancy: TenancyConfig | None = None,
) -> str:
    """Render a complete pgTAP script."""
    base_testable = [c for c in cells if c.expected in (Expected.ALLOW, Expected.DENY)]
    conditional = []
    if seed_state and tenancy:
        conditional = list(_conditional_cells_with_data(cells, seed_state))

    all_testable = base_testable + [pair[0] for pair in conditional]
    by_table: dict[str, list[MatrixCell]] = defaultdict(list)
    by_table_conditional: dict[str, list[tuple[MatrixCell, dict, dict]]] = defaultdict(list)
    for cell in base_testable:
        by_table[cell.qualified_table].append(cell)
    for cell, actor, target in conditional:
        by_table_conditional[cell.qualified_table].append((cell, actor, target))

    out = StringIO()
    out.write("-- rlsgrid pgTAP suite — generated, do not edit by hand.\n")
    if header_note:
        out.write(f"-- {header_note}\n")
    if conditional:
        out.write(f"-- CONDITIONAL coverage uses seeded tenants from state file ({len(conditional)} cells).\n")
    out.write("BEGIN;\n")
    out.write("CREATE EXTENSION IF NOT EXISTS pgtap;\n")
    out.write(f"SELECT plan({len(all_testable)});\n\n")

    all_qualified = sorted(set(by_table.keys()) | set(by_table_conditional.keys()))
    for qualified_table in all_qualified:
        out.write(f"-- ── {qualified_table} ──\n")
        for cell in by_table.get(qualified_table, []):
            out.write(_render_cell(cell))
            out.write("\n")
        for cell, actor, target in by_table_conditional.get(qualified_table, []):
            out.write(_render_conditional_cell(cell, actor, target, tenancy))  # type: ignore[arg-type]
            out.write("\n")

    out.write("SELECT * FROM finish();\n")
    out.write("ROLLBACK;\n")
    return out.getvalue()


def _conditional_cells_with_data(
    cells: list[MatrixCell],
    seed_state: dict[str, Any],
):
    """Pair each CONDITIONAL cell with two tenants that have data on its table."""
    tenants = seed_state.get("tenants", [])
    if len(tenants) < 2:
        return
    for cell in cells:
        if cell.expected is not Expected.CONDITIONAL:
            continue
        if _is_bypass_role(cell.role):
            continue
        target = tenants[1]
        if cell.operation in ("UPDATE", "DELETE") and not target.get(
            "rows_per_table", {}
        ).get(cell.qualified_table):
            continue
        yield cell, tenants[0], target


def _render_conditional_cell(
    cell: MatrixCell,
    actor: dict[str, Any],
    target: dict[str, Any],
    tenancy: TenancyConfig,
) -> str:
    qualified = _quote_qualified(cell.schema, cell.table)
    tenant_col = tenancy.tenant_column
    claim_setter = _render_claim_setter(tenancy, actor)
    role_set = f'SET LOCAL ROLE {_quote_ident(cell.role)};\n{claim_setter}\n'

    if cell.operation == "SELECT":
        test_name = _quote_literal(
            f"{cell.role} as actor cannot SELECT target rows on {cell.qualified_table}"
        )
        return (
            role_set
            + "SELECT is(\n"
            + f"  (SELECT count(*) FROM {qualified} WHERE {_quote_ident(tenant_col)} = "
            + f"{_quote_literal(target['tenant_id'])}),\n"
            + "  0::bigint,\n"
            + f"  {test_name}\n"
            + ");\n"
            + "RESET ROLE;\n"
        )

    if cell.operation == "INSERT":
        test_name = _quote_literal(
            f"{cell.role} as actor cannot INSERT target-owned row on {cell.qualified_table}"
        )
        insert_sql = (
            f"INSERT INTO {qualified} ({_quote_ident(tenant_col)}) "
            f"VALUES ({_quote_literal(target['tenant_id'])})"
        )
        return (
            role_set
            + "SELECT throws_ok(\n"
            + f"  $rlsgrid${insert_sql}$rlsgrid$,\n"
            + "  '42501', NULL,\n"
            + f"  {test_name}\n"
            + ");\n"
            + "RESET ROLE;\n"
        )

    # UPDATE / DELETE — assert 0 rows affected.
    target_rows = target.get("rows_per_table", {}).get(cell.qualified_table, [])
    if not target_rows:
        return f"-- skipped {cell.role} {cell.operation} on {cell.qualified_table}: no target rows\n"
    pk_dict = target_rows[0]
    pk_cols = list(pk_dict.keys())
    where = " AND ".join(f"{_quote_ident(c)} = {_quote_literal(str(pk_dict[c]))}" for c in pk_cols)

    if cell.operation == "UPDATE":
        set_clause = ", ".join(f"{_quote_ident(c)} = {_quote_ident(c)}" for c in pk_cols)
        cte = f"UPDATE {qualified} SET {set_clause} WHERE {where} RETURNING 1"
        test_name = _quote_literal(
            f"{cell.role} as actor cannot UPDATE target-owned row on {cell.qualified_table}"
        )
    else:  # DELETE
        cte = f"DELETE FROM {qualified} WHERE {where} RETURNING 1"
        test_name = _quote_literal(
            f"{cell.role} as actor cannot DELETE target-owned row on {cell.qualified_table}"
        )
    return (
        role_set
        + f"WITH affected AS ({cte})\n"
        + f"SELECT is((SELECT count(*) FROM affected), 0::bigint, {test_name});\n"
        + "RESET ROLE;\n"
    )


def _render_claim_setter(tenancy: TenancyConfig, actor: dict[str, Any]) -> str:
    rendered = {
        name: template.format(user_id=actor["user_id"], tenant_id=actor["tenant_id"])
        for name, template in tenancy.jwt_claims.items()
    }
    if tenancy.jwt_shape == "json":
        return (
            "SELECT set_config('request.jwt.claims', "
            f"{_quote_literal(json.dumps(rendered))}, true);"
        )
    lines = []
    for name, value in rendered.items():
        lines.append(
            f"SELECT set_config('request.jwt.claim.{name}', {_quote_literal(value)}, true);"
        )
    return "\n".join(lines)


_BYPASS_ROLES = {"service_role", "postgres", "supabase_admin"}


def _is_bypass_role(role: str) -> bool:
    return role in _BYPASS_ROLES


def _render_cell(cell: MatrixCell) -> str:
    qualified = _quote_qualified(cell.schema, cell.table)
    test_name = _quote_literal(
        f"{cell.role} can {cell.operation} {cell.qualified_table}"
        if cell.expected is Expected.ALLOW
        else f"{cell.role} cannot {cell.operation} {cell.qualified_table}"
    )

    probe = _probe_sql(qualified, cell.operation)

    if cell.expected is Expected.ALLOW:
        return (
            f"SET LOCAL ROLE {_quote_ident(cell.role)};\n"
            f"SELECT lives_ok($rlsgrid${probe}$rlsgrid$, {test_name});\n"
            f"RESET ROLE;\n"
        )
    return (
        f"SET LOCAL ROLE {_quote_ident(cell.role)};\n"
        f"SELECT throws_ok($rlsgrid${probe}$rlsgrid$, '42501', NULL, {test_name});\n"
        f"RESET ROLE;\n"
    )


def _probe_sql(qualified: str, operation: str) -> str:
    """Build the smallest possible statement that triggers the RLS check.

    The probes use `LIMIT 0` / `WHERE false` where possible so they never have
    to read or write user rows — only the policy enforcement is exercised.
    """
    if operation == "SELECT":
        return f"SELECT * FROM {qualified} LIMIT 0"
    if operation == "INSERT":
        return f"INSERT INTO {qualified} SELECT * FROM {qualified} WHERE false"
    if operation == "UPDATE":
        return f"UPDATE {qualified} SET ctid = ctid WHERE false"
    if operation == "DELETE":
        return f"DELETE FROM {qualified} WHERE false"
    raise ValueError(f"Unknown operation: {operation}")


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _quote_qualified(schema: str, table: str) -> str:
    return f"{_quote_ident(schema)}.{_quote_ident(table)}"


def _quote_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
