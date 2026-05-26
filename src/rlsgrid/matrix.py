"""Compute the role × table × operation matrix and expected outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .config import Config
from .introspect import IntrospectionResult, PolicyInfo, TableInfo

OPERATIONS: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")


class Expected(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"  # policy USING/WITH CHECK gates rows — runtime decides
    UNRESTRICTED = "unrestricted"  # RLS not enabled at all on table


@dataclass(frozen=True)
class MatrixCell:
    role: str
    role_purpose: str
    schema: str
    table: str
    operation: str
    expected: Expected
    applicable_policies: tuple[str, ...]  # policy names that match this cell

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"


def build_matrix(
    introspection: IntrospectionResult,
    config: Config,
) -> list[MatrixCell]:
    """Walk every (role, table, operation) and classify expected outcome.

    Rules:
    - If RLS is not enabled on the table → UNRESTRICTED (no isolation at DB level).
    - If RLS is enabled but no permissive policy applies to (role, command) → DENY.
    - If at least one permissive policy applies and has no USING expression → ALLOW.
    - Otherwise → CONDITIONAL (policy gates which rows; runtime check needed).

    `service_role`, `postgres`, and `supabase_admin` bypass RLS unless FORCE RLS is
    set. We surface that explicitly as UNRESTRICTED so authors notice.
    """
    cells: list[MatrixCell] = []
    role_entries = config.roles.roles or {"authenticated": "default"}

    for table in introspection.tables:
        for role, purpose in role_entries.items():
            for op in OPERATIONS:
                expected, applicable = _classify(table, role, op, introspection.policies_for(table.schema, table.name))
                cells.append(
                    MatrixCell(
                        role=role,
                        role_purpose=purpose,
                        schema=table.schema,
                        table=table.name,
                        operation=op,
                        expected=expected,
                        applicable_policies=tuple(p.name for p in applicable),
                    )
                )
    return cells


def _classify(
    table: TableInfo,
    role: str,
    operation: str,
    policies: list[PolicyInfo],
) -> tuple[Expected, list[PolicyInfo]]:
    if not table.rls_enabled:
        return Expected.UNRESTRICTED, []

    if _is_bypass_role(role) and not table.rls_forced:
        return Expected.UNRESTRICTED, []

    applicable = [
        p
        for p in policies
        if p.permissive
        and (p.command == operation or p.command == "ALL")
        and (not p.roles or role in p.roles or "public" in p.roles)
    ]

    if not applicable:
        return Expected.DENY, []

    has_gate = any(p.qual or p.with_check for p in applicable)
    if has_gate:
        return Expected.CONDITIONAL, applicable
    return Expected.ALLOW, applicable


_BYPASS_ROLES = {"service_role", "postgres", "supabase_admin"}


def _is_bypass_role(role: str) -> bool:
    return role in _BYPASS_ROLES


def summarize(cells: list[MatrixCell]) -> dict[str, int]:
    counts: dict[str, int] = {e.value: 0 for e in Expected}
    for cell in cells:
        counts[cell.expected.value] += 1
    return counts
