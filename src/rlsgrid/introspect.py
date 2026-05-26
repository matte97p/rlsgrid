"""Postgres introspection — read schemas, tables, RLS policies, roles."""

from __future__ import annotations

from dataclasses import dataclass, field

import psycopg

from .config import Config


@dataclass(frozen=True)
class TableInfo:
    schema: str
    name: str
    rls_enabled: bool
    rls_forced: bool

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class PolicyInfo:
    schema: str
    table: str
    name: str
    permissive: bool
    roles: tuple[str, ...]
    command: str  # SELECT | INSERT | UPDATE | DELETE | ALL
    qual: str | None  # USING expression
    with_check: str | None  # WITH CHECK expression

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass(frozen=True)
class ColumnInfo:
    schema: str
    table: str
    name: str
    type_name: str
    nullable: bool
    has_default: bool


@dataclass(frozen=True)
class ForeignKeyInfo:
    schema: str
    table: str
    column: str
    ref_schema: str
    ref_table: str
    ref_column: str


@dataclass
class IntrospectionResult:
    tables: list[TableInfo] = field(default_factory=list)
    policies: list[PolicyInfo] = field(default_factory=list)
    db_roles: list[str] = field(default_factory=list)
    columns: list[ColumnInfo] = field(default_factory=list)
    foreign_keys: list[ForeignKeyInfo] = field(default_factory=list)
    primary_keys: dict[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    enum_labels: dict[str, list[str]] = field(default_factory=dict)
    tables_with_checks: set[tuple[str, str]] = field(default_factory=set)

    def policies_for(self, schema: str, table: str) -> list[PolicyInfo]:
        return [p for p in self.policies if p.schema == schema and p.table == table]

    def rls_enabled_tables(self) -> list[TableInfo]:
        return [t for t in self.tables if t.rls_enabled]

    def tables_without_rls(self) -> list[TableInfo]:
        return [t for t in self.tables if not t.rls_enabled]

    def columns_of(self, schema: str, table: str) -> list[ColumnInfo]:
        return [c for c in self.columns if c.schema == schema and c.table == table]

    def foreign_keys_of(self, schema: str, table: str) -> list[ForeignKeyInfo]:
        return [f for f in self.foreign_keys if f.schema == schema and f.table == table]

    def pk_of(self, schema: str, table: str) -> tuple[str, ...]:
        return self.primary_keys.get((schema, table), ())

    def has_column(self, schema: str, table: str, column: str) -> bool:
        return any(c.name == column for c in self.columns_of(schema, table))

    def has_check_constraints(self, schema: str, table: str) -> bool:
        return (schema, table) in self.tables_with_checks

    def labels_for_enum(self, type_name: str) -> list[str] | None:
        return self.enum_labels.get(type_name)


_TABLE_QUERY = """
SELECT n.nspname AS schema,
       c.relname AS table,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND NOT (n.nspname = ANY(%s))
  AND (%s::text[] IS NULL OR n.nspname = ANY(%s))
ORDER BY n.nspname, c.relname
"""

_POLICY_QUERY = """
SELECT schemaname,
       tablename,
       policyname,
       permissive,
       roles,
       cmd,
       qual,
       with_check
FROM pg_policies
WHERE NOT (schemaname = ANY(%s))
ORDER BY schemaname, tablename, policyname
"""

_ROLES_QUERY = """
SELECT rolname
FROM pg_roles
WHERE rolname NOT LIKE 'pg\\_%' ESCAPE '\\'
ORDER BY rolname
"""

_COLUMN_QUERY = """
SELECT n.nspname AS schema,
       cl.relname AS table,
       a.attname AS name,
       t.typname AS type_name,
       NOT a.attnotnull AS nullable,
       (d.adbin IS NOT NULL) AS has_default
FROM pg_attribute a
JOIN pg_class cl ON cl.oid = a.attrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_type t ON t.oid = a.atttypid
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attnum > 0
  AND NOT a.attisdropped
  AND cl.relkind = 'r'
  AND NOT (n.nspname = ANY(%s))
ORDER BY n.nspname, cl.relname, a.attnum
"""

_FK_QUERY = """
SELECT n.nspname AS schema,
       cl.relname AS table,
       a.attname AS column,
       rn.nspname AS ref_schema,
       rcl.relname AS ref_table,
       ra.attname AS ref_column
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_class rcl ON rcl.oid = con.confrelid
JOIN pg_namespace rn ON rn.oid = rcl.relnamespace
JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
JOIN unnest(con.confkey) WITH ORDINALITY AS rk(attnum, ord) ON rk.ord = k.ord
JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attnum = k.attnum
JOIN pg_attribute ra ON ra.attrelid = rcl.oid AND ra.attnum = rk.attnum
WHERE con.contype = 'f'
  AND NOT (n.nspname = ANY(%s))
ORDER BY n.nspname, cl.relname, k.ord
"""

_PK_QUERY = """
SELECT n.nspname AS schema,
       cl.relname AS table,
       a.attname AS column,
       k.ord
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attnum = k.attnum
WHERE con.contype = 'p'
  AND NOT (n.nspname = ANY(%s))
ORDER BY n.nspname, cl.relname, k.ord
"""

_ENUM_QUERY = """
SELECT t.typname AS type_name,
       e.enumlabel AS label
FROM pg_type t
JOIN pg_enum e ON e.enumtypid = t.oid
JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE NOT (n.nspname = ANY(%s))
ORDER BY t.typname, e.enumsortorder
"""

_CHECK_QUERY = """
SELECT DISTINCT n.nspname AS schema,
       cl.relname AS table
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
WHERE con.contype = 'c'
  AND NOT (n.nspname = ANY(%s))
"""


def introspect(config: Config) -> IntrospectionResult:
    """Connect to the configured DB and dump RLS-relevant metadata."""
    exclude_schemas = list(config.exclude.schemas) or ["pg_catalog", "information_schema"]
    search_path = list(config.connection.schema_search_path) if config.connection.schema_search_path else None

    result = IntrospectionResult()
    with psycopg.connect(config.connection.url) as conn, conn.cursor() as cur:
        cur.execute(_TABLE_QUERY, (exclude_schemas, search_path, search_path))
        for row in cur.fetchall():
            schema, name, rls_enabled, rls_forced = row
            if _is_excluded_table(schema, name, config):
                continue
            result.tables.append(
                TableInfo(
                    schema=schema,
                    name=name,
                    rls_enabled=bool(rls_enabled),
                    rls_forced=bool(rls_forced),
                )
            )

        cur.execute(_POLICY_QUERY, (exclude_schemas,))
        for row in cur.fetchall():
            schema, table, name, permissive, roles, cmd, qual, with_check = row
            if _is_excluded_table(schema, table, config):
                continue
            result.policies.append(
                PolicyInfo(
                    schema=schema,
                    table=table,
                    name=name,
                    permissive=(permissive == "PERMISSIVE" or permissive is True),
                    roles=tuple(roles or ()),
                    command=cmd or "ALL",
                    qual=qual,
                    with_check=with_check,
                )
            )

        cur.execute(_ROLES_QUERY)
        result.db_roles = [r[0] for r in cur.fetchall()]

        cur.execute(_COLUMN_QUERY, (exclude_schemas,))
        for row in cur.fetchall():
            schema, table, name, type_name, nullable, has_default = row
            if _is_excluded_table(schema, table, config):
                continue
            result.columns.append(
                ColumnInfo(
                    schema=schema,
                    table=table,
                    name=name,
                    type_name=type_name,
                    nullable=bool(nullable),
                    has_default=bool(has_default),
                )
            )

        cur.execute(_FK_QUERY, (exclude_schemas,))
        for row in cur.fetchall():
            schema, table, column, ref_schema, ref_table, ref_column = row
            if _is_excluded_table(schema, table, config):
                continue
            result.foreign_keys.append(
                ForeignKeyInfo(
                    schema=schema,
                    table=table,
                    column=column,
                    ref_schema=ref_schema,
                    ref_table=ref_table,
                    ref_column=ref_column,
                )
            )

        cur.execute(_PK_QUERY, (exclude_schemas,))
        pk_acc: dict[tuple[str, str], list[str]] = {}
        for row in cur.fetchall():
            schema, table, column, _ord = row
            if _is_excluded_table(schema, table, config):
                continue
            pk_acc.setdefault((schema, table), []).append(column)
        result.primary_keys = {k: tuple(v) for k, v in pk_acc.items()}

        cur.execute(_ENUM_QUERY, (exclude_schemas,))
        enum_acc: dict[str, list[str]] = {}
        for row in cur.fetchall():
            type_name, label = row
            enum_acc.setdefault(type_name, []).append(label)
        result.enum_labels = enum_acc

        cur.execute(_CHECK_QUERY, (exclude_schemas,))
        for row in cur.fetchall():
            schema, table = row
            if _is_excluded_table(schema, table, config):
                continue
            result.tables_with_checks.add((schema, table))

    return result


def _is_excluded_table(schema: str, name: str, config: Config) -> bool:
    qualified = f"{schema}.{name}"
    for pattern in config.exclude.tables:
        if pattern in (qualified, name):
            return True
        if pattern.endswith(".*") and qualified.startswith(pattern[:-1]):
            return True
        if pattern.endswith("*") and qualified.startswith(pattern[:-1]):
            return True
    return False
