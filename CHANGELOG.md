# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-05-27

Fewer steps, no manual config, nothing left behind.

### Added
- `rlsgrid init --from-db` reads the live schema and writes an annotated
  config: it guesses the tenant column (preferring foreign keys named like
  `tenant_id` / `org_id` / `account_id` / …), detects the tenant root table
  via the FK graph, recognises Supabase (roles + schema excludes), and lists
  its detection notes so you can sanity-check them.
- `rlsgrid check` — the headline command. Seeds synthetic tenants, fuzzes
  cross-tenant access, and tears everything down in one shot. Exit 1 on any
  breach, no state files, nothing left in the database. Ideal for a first run
  or a CI gate.
- `rlsgrid fuzz --cleanup/--no-cleanup` (default `--cleanup`) removes the
  synthetic tenants the run seeded.

### Fixed
- Cross-tenant SELECT fuzz on the tenant root table silently errored
  (`column "org_id" does not exist`) and was skipped — so the root table,
  where tenant identity lives, was never actually probed. SELECT now matches
  the target's rows by their seeded primary keys, like UPDATE/DELETE.

## [0.1.2] — 2026-05-27

### Added
- Clean connection-error UX: a bad or unreachable `connection.url` now exits
  with a one-line message and code 4 instead of a psycopg traceback.
- `rlsgrid fuzz` reports *why* probes were skipped (no target row, no primary
  key, access-function unresolved, …) in both the table and `--json` output.
- Real pgTAP execution in CI: the generated suite is run with `pg_prove`
  against Postgres 16 + pgTAP, so "rlsgrid emits a passing pgTAP suite" is
  proven, not just asserted non-empty.
- Coverage floor (`--cov-fail-under=50`) on the unit job.
- Per-stack config recipes in `docs/RECIPES.md` (Supabase, Prisma, Drizzle,
  SQLAlchemy/Alembic, Rails, function mode).
- README demo image rendered from real `plan` + `fuzz` output.

### Verified
- Cross-schema topological seeding and tenant-root detection are covered by
  unit tests; the full pipeline runs against a rich multi-tenant schema in CI.

## [0.1.1] — 2026-05-27

Correctness pass driven by running the full pipeline against a rich
multi-tenant schema (FK chains, composite PKs, enums, CHECK constraints,
a no-RLS table, a service-role-only table). Several bugs that the toy
example schema could never surface are fixed here.

### Fixed
- **Tenant-root seeding.** When the tenant is keyed on a root table's own PK
  and children reference it through `tenant_column` (e.g. `orgs.id` ←
  `projects.org_id`), the seeder previously skipped the root table and every
  child INSERT failed its foreign key — producing zero seeded rows and a
  false "no breach" fuzz result. The seeder now detects the root table via
  the FK graph and seeds it first.
- **pgTAP probes asserted the wrong thing.** RLS denial is silent (zero rows),
  not a `42501`, so the old `throws_ok` assertions failed for the wrong
  reason. Base probes are now grant-aware: a missing privilege asserts
  `throws_ok('42501')`, an RLS-denied-but-granted SELECT asserts
  `is(count, 0)`, and an allowed SELECT asserts `lives_ok`.
- **Invalid UPDATE probe.** The UPDATE probe used `SET ctid = ctid`, which
  Postgres rejects (`cannot assign to system column`). It now self-assigns a
  real primary-key column.
- **CONDITIONAL SELECT on the root table.** The cross-tenant SELECT assertion
  assumed every table carries `tenant_column`; it now identifies the target's
  rows by their seeded primary keys, which also works for the root table.

### Added
- GRANT introspection (`information_schema.role_table_grants`) so the matrix
  and pgTAP emitter can tell a privilege denial apart from an RLS denial.
- Rich multi-tenant example under `examples/multitenant/` exercised end to
  end in CI.

### Changed
- Cross-tenant INSERT coverage moved entirely to the runtime fuzz (which can
  build a fully valid row); the static pgTAP suite no longer emits INSERT
  CONDITIONAL probes.

## [0.1.0 addendum]

### Added
- GitHub Action `matte97p/rlsgrid@v1` lives in this repo (was previously a
  separate `matte97p/rlsgrid-action` repo, now archived). Composite action
  with `command`, `config`, `database-url`, `tenants`, `python-version`,
  `version`, `pgtap-out`, `fail-on-breach` inputs and `result-json` +
  `breach-count` outputs.

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
