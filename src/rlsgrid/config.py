"""Config loader for rlsgrid.toml."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class ConnectionConfig:
    url: str
    schema_search_path: list[str] = field(default_factory=lambda: ["public"])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionConfig:
        url = data.get("url", "")
        if url.startswith("env:"):
            env_name = url.removeprefix("env:")
            resolved = os.environ.get(env_name)
            if not resolved:
                raise ValueError(f"connection.url references env var {env_name} which is not set")
            url = resolved
        return cls(
            url=url,
            schema_search_path=data.get("schema_search_path", ["public"]),
        )


@dataclass
class TenancyConfig:
    """How multi-tenancy isolation is implemented in the target DB.

    mode="jwt": Supabase-classic. Policies read tenant from JWT claim.
    mode="function": Access control delegated to SQL function (e.g. GeoSuite).

    `jwt_shape` controls how the fuzzer simulates a logged-in user:
    - "json" (Supabase v2 default): set `request.jwt.claims` to a single
      JSON object containing every claim. This is what `auth.jwt()` reads.
    - "individual": set each claim as its own GUC, e.g.
      `request.jwt.claim.sub`. Legacy PostgREST behaviour.

    `jwt_claims` maps claim name → value template, with `{user_id}` and
    `{tenant_id}` placeholders that the fuzzer substitutes per actor.
    """

    mode: str = "jwt"
    tenant_column: str = "tenant_id"
    user_id_column: str = "user_id"
    auth_function: str = "auth.uid()"
    access_function: str | None = None
    jwt_shape: str = "json"
    jwt_claims: dict[str, str] = field(
        default_factory=lambda: {"sub": "{user_id}", "tenant_id": "{tenant_id}"}
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TenancyConfig:
        defaults = cls()
        return cls(
            mode=data.get("mode", defaults.mode),
            tenant_column=data.get("tenant_column", defaults.tenant_column),
            user_id_column=data.get("user_id_column", defaults.user_id_column),
            auth_function=data.get("auth_function", defaults.auth_function),
            access_function=data.get("access_function"),
            jwt_shape=data.get("jwt_shape", defaults.jwt_shape),
            jwt_claims=dict(data.get("jwt_claims", defaults.jwt_claims)),
        )


@dataclass
class RolesConfig:
    """Role names to introspect and seed.

    Each entry is a Postgres role plus a logical purpose tag. The tag is
    surfaced in reports and lets fuzz strategies pick "attacker" vs "victim"
    roles automatically.
    """

    roles: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RolesConfig:
        return cls(roles=dict(data))

    def names(self) -> list[str]:
        return list(self.roles.keys())


@dataclass
class FuzzConfig:
    iterations: int = 200
    seed: int = 42
    stop_on_first_breach: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FuzzConfig:
        return cls(
            iterations=int(data.get("iterations", 200)),
            seed=int(data.get("seed", 42)),
            stop_on_first_breach=bool(data.get("stop_on_first_breach", False)),
        )


@dataclass
class ExcludeConfig:
    schemas: list[str] = field(default_factory=lambda: ["pg_catalog", "information_schema"])
    tables: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExcludeConfig:
        return cls(
            schemas=data.get("schemas", ["pg_catalog", "information_schema"]),
            tables=data.get("tables", []),
        )


@dataclass
class SafetyConfig:
    forbid_url_patterns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SafetyConfig:
        return cls(forbid_url_patterns=list(data.get("forbid_url_patterns", [])))


@dataclass
class Config:
    connection: ConnectionConfig
    tenancy: TenancyConfig = field(default_factory=TenancyConfig)
    roles: RolesConfig = field(default_factory=RolesConfig)
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)
    exclude: ExcludeConfig = field(default_factory=ExcludeConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)

    @classmethod
    def load(cls, path: str | Path) -> Config:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
        return cls(
            connection=ConnectionConfig.from_dict(raw.get("connection", {})),
            tenancy=TenancyConfig.from_dict(raw.get("tenancy", {})),
            roles=RolesConfig.from_dict(raw.get("roles", {})),
            fuzz=FuzzConfig.from_dict(raw.get("fuzz", {})),
            exclude=ExcludeConfig.from_dict(raw.get("exclude", {})),
            safety=SafetyConfig.from_dict(raw.get("safety", {})),
        )


DEFAULT_CONFIG_TEMPLATE = """# rlsgrid.toml — Row-Level Security test matrix config

[connection]
# Postgres connection string. Prefix with "env:" to read from environment.
url = "env:DATABASE_URL"
schema_search_path = ["public"]

[tenancy]
# "jwt" for Supabase-classic policies driven by auth.uid() / auth.jwt().
# "function" when access is delegated to a SQL helper (e.g. has_access(user, row)).
mode = "jwt"
tenant_column = "tenant_id"
user_id_column = "user_id"
auth_function = "auth.uid()"
# access_function = "check_user_has_access_to_store(p_user_id, p_store_id)"

[roles]
# role-name = "purpose label" — surfaced in reports + fuzz strategies.
authenticated = "logged-in supabase user"
anon = "public unauthenticated"
service_role = "bypass — should never be exposed client-side"

[fuzz]
iterations = 200
seed = 42
stop_on_first_breach = false

[exclude]
schemas = ["pg_catalog", "information_schema", "auth", "storage", "graphql", "extensions", "realtime", "supabase_functions"]
tables = []

[safety]
# Refuse to run write-capable commands (seed, fuzz) if DATABASE_URL contains
# any of these substrings. Override with RLSGRID_I_KNOW_WHAT_IM_DOING=1.
forbid_url_patterns = ["prod", "production"]

# JWT shape — uncomment to override defaults set in [tenancy].
# [tenancy]
# jwt_shape = "json"  # "json" (Supabase v2) or "individual" (legacy)
# jwt_claims = { sub = "{user_id}", tenant_id = "{tenant_id}" }
"""
