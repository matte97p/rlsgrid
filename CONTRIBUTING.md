# Contributing to rlsgrid

Thanks for your interest. rlsgrid is small on purpose — every addition is
weighed against "does this make a real RLS bug easier to catch?"

## Dev setup

```bash
git clone https://github.com/matte97p/rlsgrid
cd rlsgrid
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Running against a real Postgres

The unit tests do not need a DB. Integration tests do.

```bash
docker run -d --name rlsgrid-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
psql postgresql://postgres:postgres@localhost:5432/postgres -f examples/blog/schema.sql
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres rlsgrid introspect --config examples/rlsgrid.toml
```

## What we welcome

- New tenancy patterns (Prisma row-level helpers, Auth.js, custom JWT shapes).
- More emitters (`pytest`, `vitest`, `jest`).
- Edge cases in policy classification — open an issue with a SQL repro.

## What we push back on

- Pulling in heavy deps just to format output.
- AI-based policy generation. There are already projects for that; rlsgrid
  treats your existing policies as ground truth and tests them.
