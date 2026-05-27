"""SARIF 2.1.0 output for fuzz breaches.

Lets `rlsgrid check`/`fuzz` produce a report that GitHub code scanning can
ingest (upload-sarif action), so cross-tenant leaks show up in the repo's
Security tab next to other static-analysis findings.
"""

from __future__ import annotations

from typing import Any

from .fuzz.chaos import Breach

_RULE_ID = "cross-tenant-leak"
_INFO_URI = "https://github.com/matte97p/rlsgrid"


def build_sarif(breaches: list[Breach], *, version: str) -> dict[str, Any]:
    results = [
        {
            "ruleId": _RULE_ID,
            "level": "error",
            "message": {
                "text": (
                    f"{b.actor_role} (tenant {b.actor_tenant}) reached tenant "
                    f"{b.target_tenant}'s rows on {b.schema}.{b.table} via "
                    f"{b.operation}: {b.detail}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"{b.schema}/{b.table}"}
                    },
                    "logicalLocations": [
                        {"name": f"{b.schema}.{b.table}", "kind": "table"}
                    ],
                }
            ],
            "partialFingerprints": {
                "rlsgrid/leak": f"{b.actor_role}:{b.schema}.{b.table}:{b.operation}"
            },
        }
        for b in breaches
    ]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rlsgrid",
                        "version": version,
                        "informationUri": _INFO_URI,
                        "rules": [
                            {
                                "id": _RULE_ID,
                                "name": "CrossTenantLeak",
                                "shortDescription": {
                                    "text": "One tenant's data is reachable from another tenant's session."
                                },
                                "fullDescription": {
                                    "text": (
                                        "rlsgrid seeded synthetic tenants and an actor in one "
                                        "tenant was able to read, insert, update, or delete rows "
                                        "owned by another tenant — a Row-Level Security isolation failure."
                                    )
                                },
                                "helpUri": _INFO_URI,
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
