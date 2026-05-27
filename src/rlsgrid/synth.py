"""Synthetic value generation for fixture seeding and write probes.

Kept in its own module so the seeder and the fuzz probes derive values from
the same logic, and so adding new type families (range, geometry, …) only
touches one file.
"""

from __future__ import annotations

import re
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


def _num(s: str) -> object:
    return float(s) if "." in s else int(s)


def satisfy_check(defs: list[str], column: str) -> object | None:
    """Pick a value satisfying simple CHECK constraints on `column`, or None.

    Handles the common shapes from `pg_get_constraintdef`:
    - `col = ANY (ARRAY['a'::text, 'b'::text])`  → 'a'
    - `col = 'x'::text` / `col = 5`              → 'x' / 5
    - `col >= 1 AND col <= 5`                    → 1
    - `col > 0`                                  → 1
    - `col <= 100` (no lower bound)              → 100
    Anything more complex returns None and the caller falls back to synth.
    """
    col = re.escape(column)
    for d in defs:
        m = re.search(rf"\b{col}\b\s*=\s*ANY\s*\(ARRAY\[(.*?)\]", d, re.S)
        if m:
            strings = re.findall(r"'([^']*)'", m.group(1))
            if strings:
                return strings[0]
            nums = re.findall(r"-?\d+(?:\.\d+)?", m.group(1))
            if nums:
                return _num(nums[0])
        m = re.search(rf"\b{col}\b\s*=\s*'([^']*)'", d)
        if m:
            return m.group(1)
        m = re.search(rf"\b{col}\b\s*=\s*(-?\d+(?:\.\d+)?)", d)
        if m:
            return _num(m.group(1))
        m = re.search(rf"\b{col}\b\s*>=\s*(-?\d+)", d)
        if m:
            return int(m.group(1))
        m = re.search(rf"\b{col}\b\s*>\s*(-?\d+)", d)
        if m:
            return int(m.group(1)) + 1
        m = re.search(rf"\b{col}\b\s*<=\s*(-?\d+)", d)
        if m:
            return int(m.group(1))
    return None
