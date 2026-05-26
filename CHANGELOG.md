# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Prod-guard: `seed` and `fuzz` refuse to run when `connection.url`
  matches any pattern in `[safety].forbid_url_patterns`. Set
  `RLSGRID_I_KNOW_WHAT_IM_DOING=1` to override.
- `--json` flag on `introspect`, `plan`, `seed`, and `fuzz` so CI workflows
  can consume the output without scraping Rich tables.
- Configurable JWT shape (`tenancy.jwt_shape = "json"` for Supabase v2 —
  the new default — or `"individual"` for legacy PostgREST), plus
  per-claim templates in `tenancy.jwt_claims`. The previous hard-coded
  `request.jwt.claim.{sub,tenant_id}` setup was wrong for any post-2022
  Supabase deployment.
- `seed --state-out path.json` and `fuzz --state-out path.json` persist
  the seeded tenant UUIDs and PKs for re-use.
- New `teardown` command consumes that state file and deletes the seeded
  rows so the seeder is idempotent.
- `gen pgtap --from-state path.json` emits CONDITIONAL cross-tenant
  assertions in the pgTAP suite. Each cell becomes a real
  `SELECT is(count(*), 0)` (or `throws_ok` for INSERT, or
  `WITH affected AS (UPDATE …) SELECT is(count(*), 0)` for UPDATE/DELETE)
  using the actor and target UUIDs from the state file. CONDITIONAL
  coverage is no longer fuzz-only.
- Function-mode placeholder system now accepts arbitrary `{name}` markers
  with safe Postgres parameter binding: `{user_id}`, `{tenant_id}`,
  `{target_tenant_id}`, `{target_user_id}`, `{row_id}`, and
  `{row.<column>}` for any column on the target row. Multi-arg signatures
  like `has_access({user_id}, {row.account_id}, 'view')` work out of the
  box.
- Composite primary keys are now respected by the UPDATE probe — every PK
  column is included in both the SET and WHERE clauses.
- Verified-RLS badge: `fuzz --shields-out badge.json` emits a shields.io
  endpoint payload, `fuzz --badge-out badge.svg` emits a self-contained
  SVG. Both reflect the same pass/fail outcome with leak count.

### Changed
- `seed_tenants` now returns a `SeedReport` with `tenants`, `skipped`
  (per-table reason: unresolved FK, NOT NULL violation, CHECK failure, ...)
  and `check_warnings`. The CLI surfaces all three so users can see exactly
  which tables their fuzz run will exercise.
- Schema introspection now reads `pg_enum` and `pg_constraint` (CHECK) so
  synthetic values land on valid enum labels and seeders flag CHECK-heavy
  tables instead of silently producing zero coverage.
- INSERT fuzz probe now fills every NOT NULL column without a default —
  previously it inserted only the tenant column and was rejected by `23502`
  on most real schemas, producing false-negative "no breach" reports.
- UPDATE fuzz probe now self-assigns the primary key column
  (`SET pk = pk WHERE pk = ?`) instead of touching the `ctid` system
  column, which some Postgres builds refuse.

### Known limitations
- Live smoke validation runs in CI against real Postgres 16.
  Local-only `py-pglite` reproductions hit segfaults under introspection
  query load — track upstream pglite stability, not an `rlsgrid` issue.

## [0.1.0] — 2026-05-26

### Added
- Schema introspection: tables, RLS state, policies, roles, columns, foreign
  keys, primary keys.
- `build_matrix` classifies every (role, table, operation) as
  `allow` / `deny` / `conditional` / `unrestricted`.
- pgTAP emitter producing one assertion per ALLOW/DENY cell.
- Schema-aware fixture seeder: walks FK graph in topological order, fills
  child rows with PKs from already-seeded parents so cross-tenant probes are
  meaningful instead of trivially failing on referential-integrity errors.
- Cross-tenant chaos fuzz (`rlsgrid fuzz`) with four probe types:
  SELECT leak, INSERT-with-foreign-tenant-id, UPDATE on foreign row,
  DELETE on foreign row. Probes target `CONDITIONAL` and `ALLOW` matrix cells
  directly instead of picking tables at random.
- Function mode (`tenancy.mode = "function"`): when access is decided by a
  SQL helper instead of by RLS, the fuzz harness calls the helper with
  cross-tenant args and asserts it returns false.
- CLI: `init`, `introspect`, `plan`, `gen pgtap`, `seed`, `fuzz`.
- Example Supabase-style blog schema in `examples/blog/schema.sql`.
