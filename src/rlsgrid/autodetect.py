"""Heuristics that turn a live schema into a starter rlsgrid.toml.

Pure functions over an `IntrospectionResult` so they are unit-testable
without a database. `init --from-db` connects, introspects, and feeds the
result here to produce an annotated config the user can sanity-check.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .introspect import IntrospectionResult

# Column names that usually carry the tenant foreign key, best first.
TENANT_HINTS: tuple[str, ...] = (
    "tenant_id",
    "organization_id",
    "org_id",
    "account_id",
    "workspace_id",
    "company_id",
    "team_id",
    "store_id",
    "project_id",
    "customer_id",
)

SUPABASE_ROLES = {"authenticated", "anon", "service_role"}

# Schemas Supabase ships that should never be in scope for tenant tests.
SUPABASE_EXCLUDE = [
    "pg_catalog",
    "information_schema",
    "auth",
    "storage",
    "graphql",
    "graphql_public",
    "extensions",
    "realtime",
    "supabase_functions",
    "vault",
    "pgsodium",
    "pgsodium_masks",
    "net",
]


@dataclass
class Detection:
    tenant_column: str
    tenant_root: tuple[str, str, str] | None  # (schema, table, col)
    is_supabase: bool
    roles: dict[str, str] = field(default_factory=dict)
    exclude_schemas: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def detect(introspection: IntrospectionResult) -> Detection:
    is_supabase = SUPABASE_ROLES.issubset(set(introspection.db_roles))
    tenant_column = _guess_tenant_column(introspection)
    tenant_root = _detect_root(introspection, tenant_column)
    roles = _guess_roles(introspection, is_supabase)
    exclude = SUPABASE_EXCLUDE if is_supabase else ["pg_catalog", "information_schema"]

    notes: list[str] = []
    notes.append(
        f"tenant_column guessed as '{tenant_column}'"
        + (" (found as a foreign key)" if tenant_root else " (no FK found — verify this)")
    )
    if tenant_root:
        notes.append(
            f"tenant root table detected: {tenant_root[0]}.{tenant_root[1]} "
            f"keyed on '{tenant_root[2]}'"
        )
    notes.append("Supabase detected" if is_supabase else "plain Postgres (no Supabase roles)")
    return Detection(
        tenant_column=tenant_column,
        tenant_root=tenant_root,
        is_supabase=is_supabase,
        roles=roles,
        exclude_schemas=exclude,
        notes=notes,
    )


def _guess_tenant_column(introspection: IntrospectionResult) -> str:
    fk_cols = {fk.column for fk in introspection.foreign_keys}
    # 1. A hint name that is actually a foreign key — strongest signal.
    for hint in TENANT_HINTS:
        if hint in fk_cols:
            return hint
    # 2. Most common foreign-key column across RLS tables.
    rls_tables = {(t.schema, t.name) for t in introspection.rls_enabled_tables()}
    fk_freq = Counter(
        fk.column for fk in introspection.foreign_keys if (fk.schema, fk.table) in rls_tables
    )
    if fk_freq:
        return fk_freq.most_common(1)[0][0]
    # 3. A hint name present as a plain column.
    col_names = {c.name for c in introspection.columns}
    for hint in TENANT_HINTS:
        if hint in col_names:
            return hint
    # 4. Fallback.
    return "tenant_id"


def _detect_root(
    introspection: IntrospectionResult,
    tenant_column: str,
) -> tuple[str, str, str] | None:
    for fk in introspection.foreign_keys:
        if fk.column == tenant_column:
            return (fk.ref_schema, fk.ref_table, fk.ref_column)
    return None


def _guess_roles(introspection: IntrospectionResult, is_supabase: bool) -> dict[str, str]:
    if is_supabase:
        return {
            "authenticated": "logged-in Supabase user",
            "anon": "public unauthenticated",
            "service_role": "backend bypass — never expose client-side",
        }
    roles: dict[str, str] = {}
    for r in introspection.db_roles:
        if r in ("postgres", "supabase_admin") or r.startswith("pg_"):
            continue
        roles[r] = "application role"
    return roles or {"authenticated": "application role"}


def render_config(detection: Detection) -> str:
    """Render an annotated rlsgrid.toml from a Detection."""
    roles_lines = "\n".join(
        f'{name} = "{purpose}"' for name, purpose in detection.roles.items()
    )
    exclude_schemas = ", ".join(f'"{s}"' for s in detection.exclude_schemas)

    root_comment = ""
    if detection.tenant_root:
        s, t, c = detection.tenant_root
        root_comment = (
            f"# Tenant root table detected: {s}.{t} (keyed on {c}); "
            "rlsgrid seeds it first.\n"
        )

    jwt_block = (
        'jwt_shape = "json"\n'
        f'jwt_claims = {{ sub = "{{user_id}}", {detection.tenant_column} = "{{tenant_id}}", role = "authenticated" }}\n'
        if detection.is_supabase
        else 'jwt_shape = "json"\n'
        f'jwt_claims = {{ sub = "{{user_id}}", {detection.tenant_column} = "{{tenant_id}}" }}\n'
    )

    notes = "\n".join(f"#   - {n}" for n in detection.notes)

    return f"""# rlsgrid.toml — generated by `rlsgrid init --from-db`.
# Detection notes (verify before trusting):
{notes}

[connection]
url = "env:DATABASE_URL"
schema_search_path = ["public"]

[tenancy]
{root_comment}mode = "jwt"
tenant_column = "{detection.tenant_column}"
user_id_column = "user_id"
auth_function = "auth.uid()"
{jwt_block}
[roles]
{roles_lines}

[fuzz]
iterations = 300
seed = 42
stop_on_first_breach = false

[exclude]
schemas = [{exclude_schemas}]
tables = []

[safety]
forbid_url_patterns = ["prod", "production"]
"""
