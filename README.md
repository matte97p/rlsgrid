# rlsgrid

**Catch cross-tenant Row-Level Security leaks in Postgres and Supabase
before your users do.**

[![CI](https://github.com/matte97p/rlsgrid/actions/workflows/ci.yml/badge.svg)](https://github.com/matte97p/rlsgrid/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rlsgrid.svg)](https://pypi.org/project/rlsgrid/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

<p align="center"><img src="assets/demo.svg" alt="rlsgrid plan and fuzz output" width="760"></p>

---

## What it does

Point it at your database. rlsgrid reads the live schema and:

1. **Maps** every `role × table × operation` and labels it
   `allow` / `deny` / `conditional` / `unrestricted`.
2. **Fuzzes** for real cross-tenant leaks — it seeds synthetic tenants and
   actively tries to read, insert, update, and delete one tenant's rows from
   another tenant's session.
3. **Emits** a pgTAP suite you can run in CI.

## Why

Postgres RLS is powerful and easy to get subtly wrong: a missing
`WITH CHECK`, a `FOR ALL` where you meant `FOR SELECT`, a forgotten
`ENABLE ROW LEVEL SECURITY`, a `service_role` bypass leaking client-side.
Your application unit tests will not catch any of these — they test your code,
not the policies. rlsgrid tests the policies, against a real database.

## Use it

```bash
sudo apt install python3-venv -y
python3 -m venv ~/venvs/rlsgrid-env
source ~/venvs/rlsgrid-env/bin/activate
pip install rlsgrid
# if ipv6
export DATABASE_URL=postgresql://user:pw@host/db   # use staging, never prod
# if ipv4
getent ahosts db-host | grep STREAM | grep 4
export DATABASE_URL=postgresql://user:pw@<response>/db
rlsgrid init --from-db      # read the schema, write an annotated config
rlsgrid check --tenants 5   # seed → fuzz → teardown. exit 1 on any leak.
```

`check` is the whole loop: it leaves nothing behind and returns non-zero on a
breach, so it drops straight into CI. A leak looks like:

```
✗ 1 cross-tenant breach detected
  LEAK role=authenticated actor_tenant=a1b2 → target_tenant=c3d4
       on public.documents UPDATE: target-owned row visible across tenants
```

### In CI (GitHub Action)

```yaml
- uses: matte97p/rlsgrid@v1
  with:
    command: check
    database-url: ${{ secrets.STAGING_DB_URL }}
```

### Lower-level commands

```bash
rlsgrid introspect          # tables, RLS state, policies
rlsgrid plan --explain      # the full matrix, with a "why" column
rlsgrid gen pgtap --out tests/rls/generated.sql   # emit a pgTAP suite
rlsgrid fuzz --tenants 5    # fuzz only (auto-cleans up)
rlsgrid seed --dry-run      # show the seed plan without writing
rlsgrid check --sarif-out rls.sarif   # SARIF for GitHub code scanning
```

### From pytest

Installing rlsgrid registers a `rlsgrid` fixture, so you can gate your
existing suite:

```python
def test_no_cross_tenant_leaks(rlsgrid):
    report = rlsgrid.check()
    assert report.ok, [b.detail for b in report.breaches]
```

Point it with `--rlsgrid-config path/to/rlsgrid.toml`.

Config for your stack — Supabase, Prisma, Drizzle, SQLAlchemy, Rails,
function-based access checks — is in [docs/RECIPES.md](docs/RECIPES.md).

## How it classifies a cell

- **allow** — a permissive policy applies and gates nothing.
- **deny** — RLS is on and no policy matches the role/op.
- **conditional** — a policy applies but a `USING` / `WITH CHECK` expression
  gates which rows. This is where the fuzz earns its keep.
- **unrestricted** — RLS is off, or the role has `BYPASSRLS`. Surfaced
  explicitly so you notice when you did not mean it.

## Two enforcement models

- **RLS at the database** (the Supabase default): the fuzz finds leaks
  directly. Set `tenancy.mode = "jwt"`.
- **Access enforced by a SQL function** (e.g.
  `check_user_has_access_to_store(user_id, store_id)`): set
  `tenancy.mode = "function"` and rlsgrid calls the helper with cross-tenant
  arguments, asserting it returns false.

## How it compares

| | hand-written pgTAP | static linters | **rlsgrid** |
|---|---|---|---|
| New table lands without a test | silent | maybe | shows up in `plan` |
| Cross-tenant write leaks | only if you wrote that test | no | probed automatically |
| Function-based access | no | no | first-class |
| Setup | per-test | low | one config |

It composes with [`supabase-test-helpers`](https://github.com/usebasejump/supabase-test-helpers):
keep your bespoke business-rule pgTAP, let rlsgrid watch the floor.

## Safety

`seed`, `fuzz`, and `check` write to the database, so they refuse any URL
matching `[safety].forbid_url_patterns` (default `["prod", "production"]`).
Point `DATABASE_URL` at staging or a disposable database.

## Status

Alpha, but exercised end to end in CI against a rich multi-tenant schema and
run through `pg_prove`. The config shape may still shift before 1.0. Issues
and PRs welcome — see [CONTRIBUTING](CONTRIBUTING.md).

Built by [Matteo Perino](https://github.com/matte97p) while shipping
[GeoSuite](https://trygeosuite.it), a multi-tenant Supabase app.

## License

MIT — see [LICENSE](LICENSE).
