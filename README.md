# rlsgrid

> Schema-driven Row-Level Security test matrix generator and cross-tenant
> fuzzer for Postgres and Supabase. Point it at your database, get back a
> `role × table × operation` matrix, a pgTAP suite, and a fuzz harness that
> actively tries to leak one tenant's rows into another tenant's session.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

> Built by [Matteo Perino](https://github.com/matte97p) while shipping
> [GeoSuite](https://trygeosuite.it), a multi-tenant Supabase app with
> agency/account/store isolation layered on top of Postgres RLS. The library
> is extracted from the patterns that survived production audits.

---

## The problem

Postgres RLS is one of the most powerful access-control primitives in the
ecosystem, and one of the easiest to get subtly wrong. A missing `WITH CHECK`,
a `FOR ALL` policy where you wanted `FOR SELECT`, a forgotten
`ENABLE ROW LEVEL SECURITY`, or a `service_role` bypass that quietly leaks
into a client surface — every one of these is a tenant-isolation incident
waiting to happen, and unit tests against your application code will not
catch them.

The existing tools split into three camps:

| Tool | What it does | What it doesn't do |
|------|--------------|--------------------|
| `usebasejump/supabase-test-helpers` | pgTAP helpers you write by hand. | Generates nothing. |
| `pgrls` | Static linter (43 rules). | Doesn't execute policies. |
| `supashield` | Pentest-style scanner from outside. | Doesn't read your schema. |
| AI-based generators | LLM writes pgTAP for you. | Hallucinates, opaque, drifts. |

`rlsgrid` fills the missing slot: **read your real schema, classify what
every role can do, emit deterministic tests, then chaos-fuzz for cross-tenant
leaks at runtime.**

## Install

```bash
pip install rlsgrid
```

## Quickstart

```bash
# 1. Generate a starter config.
rlsgrid init

# 2. Point DATABASE_URL at your DB.
export DATABASE_URL=postgresql://user:pw@host/db

# 3. See what rlsgrid found.
rlsgrid introspect

# 4. See the matrix — every role × table × op cell with expected outcome.
rlsgrid plan

# 5. Emit a pgTAP suite covering every ALLOW/DENY cell.
rlsgrid gen pgtap --out tests/rls/generated.sql
pg_prove -d "$DATABASE_URL" tests/rls/generated.sql

# 6. Chaos-fuzz cross-tenant SELECT leaks.
rlsgrid fuzz --tenants 5
```

## What you get

### The matrix

```
┌────────────────┬─────────────────┬────────┬──────────────┬───────────────────┐
│ Role           │ Table           │ Op     │ Expected     │ Policies          │
├────────────────┼─────────────────┼────────┼──────────────┼───────────────────┤
│ authenticated  │ public.posts    │ SELECT │ conditional  │ posts_owner_all   │
│ authenticated  │ public.posts    │ INSERT │ conditional  │ posts_owner_all   │
│ anon           │ public.posts    │ SELECT │ deny         │ —                 │
│ service_role   │ public.posts    │ SELECT │ unrestricted │ — (BYPASSRLS)     │
└────────────────┴─────────────────┴────────┴──────────────┴───────────────────┘
```

Every cell is classified by reading `pg_policies` + `pg_class`:

- **allow** — at least one permissive policy applies and gates nothing.
- **deny** — RLS is enabled and no permissive policy matches the role/op.
- **conditional** — a policy applies but a `USING` / `WITH CHECK` expression
  gates which rows. Runtime check needed (this is where chaos-fuzz comes in).
- **unrestricted** — RLS is off or the role has `BYPASSRLS`. Surfaced
  explicitly so you notice when you didn't mean it.

### The pgTAP suite

For every ALLOW / DENY cell, rlsgrid emits a probe that exercises the policy
without touching real rows:

```sql
SET LOCAL ROLE "anon";
SELECT throws_ok(
  $rlsgrid$ SELECT * FROM "public"."posts" LIMIT 0 $rlsgrid$,
  '42501', NULL,
  'anon cannot SELECT public.posts'
);
RESET ROLE;
```

CONDITIONAL cells aren't asserted at the pgTAP layer — that's chaos-fuzz's
job, because the truth requires real per-tenant rows.

### The chaos fuzzer

`rlsgrid fuzz` seeds N synthetic tenants — walking the FK graph in
topological order so child rows reference their tenant's parent rows — then
repeatedly picks `(actor, target, cell)` triples drawn from the
`CONDITIONAL` and `ALLOW` cells of the matrix and runs four probes against
the target's data while the actor's session is active:

| Probe   | What it asks                                                       |
|---------|--------------------------------------------------------------------|
| SELECT  | Can the actor see any of target's rows?                            |
| INSERT  | Can the actor write a row stamped with the target's tenant id?     |
| UPDATE  | Can the actor mutate a row owned by the target (by PK)?            |
| DELETE  | Can the actor delete a row owned by the target (by PK)?            |

Every probe runs in its own transaction that rolls back on completion, so
the database state never moves between iterations.

```
✗ 1 breach(es) detected
  LEAK role=authenticated actor_tenant=a1b2 → target_tenant=c3d4
       on public.posts SELECT: 3 rows visible across tenants
```

### Function mode

When access is not enforced by RLS but by a backend helper — the GeoSuite
pattern, where `check_user_has_access_to_store(user_id, store_id)` is the
final gate — set `tenancy.mode = "function"` and point `access_function` at
the helper with `{user_id}` and `{row_id}` placeholders:

```toml
[tenancy]
mode = "function"
access_function = "check_user_has_access_to_store({user_id}, {row_id})"
```

The fuzz harness then iterates every `(actor, target_row)` pair across the
seeded tenants and calls the helper with cross-tenant arguments. If it ever
returns `true`, that is a breach with the same Breach shape as the RLS-mode
probes.

### JWT shape

Modern Supabase (v2+) stores every claim in a single GUC,
`request.jwt.claims`, as JSON — that's what `auth.jwt()` reads. Older
deployments set one GUC per claim (`request.jwt.claim.sub`, etc.). rlsgrid
defaults to the modern shape; override per project:

```toml
[tenancy]
jwt_shape = "json"  # or "individual"
jwt_claims = { sub = "{user_id}", tenant_id = "{tenant_id}", role = "authenticated" }
```

Both `{user_id}` and `{tenant_id}` are filled per actor before each probe.

### Prod-guard

The write-capable commands (`seed`, `fuzz`) refuse to run when the URL
matches any pattern in `[safety].forbid_url_patterns`. The default list is
`["prod", "production"]`. To override on purpose, set
`RLSGRID_I_KNOW_WHAT_IM_DOING=1` — the awkward name is intentional.

### JSON output for CI

Every read command (`introspect`, `plan`) and every write command (`seed`,
`fuzz`) accepts `--json`. The shape is stable enough to drive PR-comment
bots, dashboards, or threshold gates without parsing terminal output.

```bash
rlsgrid fuzz --json | jq '.breaches | length'
```

## Configuration

`rlsgrid.toml` lives at your repo root. The interesting part is the
`[tenancy]` block, which tells rlsgrid how isolation is supposed to work:

```toml
[tenancy]
# Supabase-classic: policies read auth.uid() from the JWT.
mode = "jwt"
tenant_column = "tenant_id"
auth_function = "auth.uid()"

# Or: access delegated to a SQL helper (e.g. GeoSuite-style).
# mode = "function"
# access_function = "check_user_has_access_to_store(p_user_id, p_store_id)"
```

The two modes exist because real production schemas don't all look like the
Supabase quickstart. The function-based mode covers the pattern where the
application layer asks Postgres "does this user have access to this row?"
via a stable function — rlsgrid will still build the matrix and the fuzz
will still find cross-tenant leaks.

### Verified-RLS badge

`fuzz` can also write a status badge so projects can advertise that they
test cross-tenant isolation in CI. Two formats:

```bash
# shields.io endpoint JSON — no asset hosting, commit the JSON file
rlsgrid fuzz --shields-out badge.json

# Static SVG — host wherever you like
rlsgrid fuzz --badge-out badge.svg
```

Embed in your project README:

```markdown
[![rlsgrid](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/USER/REPO/main/badge.json)](https://github.com/USER/REPO)
```

The badge turns green when the fuzz run reports no breaches and red as
soon as one shows up.

## When to reach for rlsgrid vs the alternatives

`usebasejump/supabase-test-helpers` is the de-facto Supabase RLS testing
toolkit. It ships a set of pgTAP helpers (`tests.authenticate_as`,
`tests.rls_enabled`, …) so you can hand-write assertions like:

```sql
SELECT tests.authenticate_as('alice');
SELECT results_eq(
  'SELECT count(*) FROM posts',
  ARRAY[1::bigint],
  'alice sees only her own posts'
);
```

That style is excellent when you have a small fixed surface and want to
encode bespoke business rules. It struggles when the surface grows: every
new role, table or operation is another pgTAP file you write and maintain
by hand, and you do not get told about regressions until someone remembers
to add the test.

`rlsgrid` solves the other half of the problem:

| | `supabase-test-helpers` | `rlsgrid` |
|---|---|---|
| Style | Hand-written pgTAP | Schema-driven generation + runtime fuzz |
| New table lands without a test | Silent | Surfaces immediately in `plan` / `gen pgtap` |
| Cross-tenant write leaks | Whatever you remember to test | Probed automatically (`fuzz` SELECT/INSERT/UPDATE/DELETE) |
| Function-based access checks | Not modelled | First-class (`tenancy.mode = "function"`) |
| CI integration | You wire it | One-step GitHub Action with JSON output |
| Setup cost | Low | Low (single `rlsgrid.toml`) |
| Best for | Encoding "this specific user must see exactly these rows" | Catching the broad class of "we forgot to lock this down" |

They compose well: keep your high-signal `supabase-test-helpers` cases for
the business rules you care about most, and let `rlsgrid` watch the floor.

## GitHub Action

The repo ships a composite GitHub Action so dropping rlsgrid into a CI
workflow is one step:

```yaml
- uses: matte97p/rlsgrid@v1
  with:
    command: fuzz
    config: rlsgrid.toml
    database-url: ${{ secrets.STAGING_DB_URL }}
    fail-on-breach: true
```

Inputs: `command` (introspect/plan/gen-pgtap/seed/fuzz), `config`,
`database-url` (required), `tenants`, `python-version`, `version` (pin a
rlsgrid release), `pgtap-out`, `fail-on-breach`.

Outputs: `result-json` (path to JSON report), `breach-count`.

Full example workflow that gates a PR on cross-tenant leaks against a
disposable Postgres service:

```yaml
name: rls-fuzz
on:
  pull_request:
    paths: ["supabase/migrations/**", "rlsgrid.toml"]
jobs:
  fuzz:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        ports: ["5432:5432"]
        options: >-
          --health-cmd="pg_isready -U postgres"
          --health-interval=5s --health-timeout=5s --health-retries=10
    steps:
      - uses: actions/checkout@v4
      - run: psql "$PG" -f supabase/migrations/*.sql
        env:
          PG: postgresql://postgres:postgres@localhost:5432/postgres
      - uses: matte97p/rlsgrid@v1
        with:
          command: fuzz
          database-url: postgresql://postgres:postgres@localhost:5432/postgres
          tenants: "5"
```

Pin to a specific release in production (`matte97p/rlsgrid@v0.1.0`).

## Status

Alpha. Stable enough to run on real schemas; the pgTAP output and config
shape may shift before 1.0. Issues and PRs welcome — see
[CONTRIBUTING](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
