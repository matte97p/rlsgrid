"""Synthetic value generation for fixture seeding and write probes.

Kept in its own module so the seeder and the fuzz probes derive values from
the same logic, and so adding new type families (range, geometry, …) only
touches one file.
"""

from __future__ import annotations

import uuid

# Built-in scalar handling for the common Postgres `typname` values.
_INT_TYPES = {"int2", "int4", "int8", "numeric", "float4", "float8"}


def synth_value(
    type_name: str,
    *,
    enum_labels: list[str] | None = None,
) -> object:
    """Return a value plausibly accepted by a column of `type_name`.

    `enum_labels`, when provided, takes precedence — the first label is
    chosen deterministically so seeded data is comparable across runs.
    """
    if enum_labels:
        return enum_labels[0]

    type_name = (type_name or "").lower()
    if "uuid" in type_name:
        return str(uuid.uuid4())
    if "json" in type_name:
        return "{}"
    if type_name in _INT_TYPES:
        return 0
    if type_name == "bool":
        return False
    if "time" in type_name or "date" in type_name:
        return None
    if type_name == "bytea":
        return b""
    if "inet" in type_name or "cidr" in type_name:
        return "0.0.0.0/0"
    return "rlsgrid-fixture"
