"""rlsgrid CLI — `rlsgrid <command>`."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .badge import from_fuzz_report, make_shields_json, make_svg
from .config import DEFAULT_CONFIG_TEMPLATE, Config
from .emitters import pgtap as pgtap_emitter
from .fixtures import seed_tenants, teardown_from_state
from .fuzz import chaos
from .introspect import introspect as run_introspect
from .matrix import Expected, build_matrix, summarize
from .safety import ProdGuardViolation, assert_safe_to_write

console = Console()


def _load(config_path: str) -> Config:
    try:
        return Config.load(config_path)
    except FileNotFoundError:
        console.print(f"[red]Config not found:[/red] {config_path}")
        console.print("Run [bold]rlsgrid init[/bold] to create one.")
        sys.exit(2)


def _guard_writes(cfg: Config) -> None:
    try:
        assert_safe_to_write(cfg.connection.url, cfg.safety.forbid_url_patterns)
    except ProdGuardViolation as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(3)


def _dump_json(payload: dict[str, Any]) -> None:
    click.echo(json.dumps(payload, indent=2, default=_json_default))


def _json_default(obj: object) -> object:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, Expected):
        return obj.value
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    raise TypeError(f"unserializable: {type(obj).__name__}")


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="rlsgrid")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Row-Level Security test matrix generator for Postgres/Supabase."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.option("--out", "out_path", default="rlsgrid.toml", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite existing config.")
def init(out_path: str, force: bool) -> None:
    """Write a starter rlsgrid.toml in the current directory."""
    path = Path(out_path)
    if path.exists() and not force:
        console.print(f"[yellow]{path} already exists.[/yellow] Pass --force to overwrite.")
        sys.exit(1)
    path.write_text(DEFAULT_CONFIG_TEMPLATE)
    console.print(f"[green]✓[/green] Wrote {path}")


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
def introspect(config_path: str, as_json: bool) -> None:
    """Print a summary of tables, RLS state, and policies."""
    cfg = _load(config_path)
    result = run_introspect(cfg)

    if as_json:
        _dump_json(
            {
                "tables": [
                    {
                        "schema": t.schema,
                        "name": t.name,
                        "rls_enabled": t.rls_enabled,
                        "rls_forced": t.rls_forced,
                        "policy_count": len(result.policies_for(t.schema, t.name)),
                    }
                    for t in result.tables
                ],
                "roles": result.db_roles,
                "policies_total": len(result.policies),
                "tables_without_rls": [
                    f"{t.schema}.{t.name}" for t in result.tables_without_rls()
                ],
            }
        )
        return

    table = Table(title="Tables", show_lines=False)
    table.add_column("Schema")
    table.add_column("Table")
    table.add_column("RLS", justify="center")
    table.add_column("Forced", justify="center")
    table.add_column("Policies", justify="right")
    for t in result.tables:
        n_pol = len(result.policies_for(t.schema, t.name))
        table.add_row(
            t.schema,
            t.name,
            "[green]on[/green]" if t.rls_enabled else "[red]off[/red]",
            "yes" if t.rls_forced else "—",
            str(n_pol),
        )
    console.print(table)

    console.print(
        f"\n[bold]Roles seen:[/bold] {len(result.db_roles)}  "
        f"[bold]Policies:[/bold] {len(result.policies)}  "
        f"[bold]Tables without RLS:[/bold] {len(result.tables_without_rls())}"
    )


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--show", type=click.Choice(["all", "deny", "allow", "conditional", "unrestricted"]), default="all")
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
def plan(config_path: str, show: str, as_json: bool) -> None:
    """Print the role × table × op matrix and expected outcomes."""
    cfg = _load(config_path)
    result = run_introspect(cfg)
    cells = build_matrix(result, cfg)
    visible = [c for c in cells if show == "all" or c.expected.value == show]

    if as_json:
        _dump_json(
            {
                "cells": [
                    {
                        "role": c.role,
                        "schema": c.schema,
                        "table": c.table,
                        "operation": c.operation,
                        "expected": c.expected.value,
                        "policies": list(c.applicable_policies),
                    }
                    for c in visible
                ],
                "summary": summarize(cells),
            }
        )
        return

    table = Table(title="Matrix", show_lines=False)
    table.add_column("Role")
    table.add_column("Table")
    table.add_column("Op")
    table.add_column("Expected")
    table.add_column("Policies", overflow="fold")

    for cell in visible:
        color = {
            Expected.ALLOW: "green",
            Expected.DENY: "red",
            Expected.CONDITIONAL: "yellow",
            Expected.UNRESTRICTED: "magenta",
        }[cell.expected]
        table.add_row(
            cell.role,
            cell.qualified_table,
            cell.operation,
            f"[{color}]{cell.expected.value}[/{color}]",
            ", ".join(cell.applicable_policies) or "—",
        )
    console.print(table)

    counts = summarize(cells)
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[green]allow={counts['allow']}[/green]  "
        f"[red]deny={counts['deny']}[/red]  "
        f"[yellow]conditional={counts['conditional']}[/yellow]  "
        f"[magenta]unrestricted={counts['unrestricted']}[/magenta]"
    )


@main.group()
def gen() -> None:
    """Emit test artifacts from the matrix."""


@gen.command("pgtap")
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--out", "out_path", default="tests/rls/generated.sql", show_default=True)
@click.option(
    "--from-state",
    "state_path",
    default=None,
    help="JSON seed state from `rlsgrid seed --state-out` — enables CONDITIONAL coverage.",
)
def gen_pgtap(config_path: str, out_path: str, state_path: str | None) -> None:
    """Emit a pgTAP SQL test suite covering ALLOW and DENY cells.

    Pass --from-state to also emit CONDITIONAL cross-tenant assertions
    using the seeded tenant UUIDs.
    """
    cfg = _load(config_path)
    result = run_introspect(cfg)
    cells = build_matrix(result, cfg)
    seed_state = None
    if state_path:
        import json as _json
        seed_state = _json.loads(Path(state_path).read_text())
    sql = pgtap_emitter.emit(
        cells,
        header_note=f"Generated by rlsgrid {__version__}",
        seed_state=seed_state,
        tenancy=cfg.tenancy if seed_state else None,
    )
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(sql)
    extra = " (with CONDITIONAL coverage)" if seed_state else ""
    console.print(
        f"[green]✓[/green] Wrote pgTAP suite to {out} ({len(cells)} cells inspected){extra}."
    )


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--tenants", default=3, show_default=True, type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
@click.option(
    "--state-out",
    "state_out",
    default=None,
    help="Persist the seeded tenant state to a JSON file (for later teardown or pgTAP gen).",
)
def seed(config_path: str, tenants: int, as_json: bool, state_out: str | None) -> None:
    """Seed N synthetic tenants into every RLS table carrying tenant_column."""
    cfg = _load(config_path)
    _guard_writes(cfg)
    result = run_introspect(cfg)
    seed_report = seed_tenants(result, cfg, tenants=tenants)
    if state_out:
        seed_report.write_state(state_out)

    if as_json:
        _dump_json(
            {
                "tenants": [
                    {
                        "tenant_id": t.tenant_id,
                        "user_id": t.user_id,
                        "rows_per_table": {k: len(v) for k, v in t.rows_by_table.items()},
                    }
                    for t in seed_report.tenants
                ],
                "skipped": [
                    {"table": q, "reason": r} for q, r in seed_report.skipped
                ],
                "check_warnings": seed_report.check_warnings,
            }
        )
        return

    console.print(f"[green]✓[/green] Seeded {len(seed_report.tenants)} tenants:")
    for t in seed_report.tenants:
        total_rows = sum(len(rs) for rs in t.rows_by_table.values())
        console.print(
            f"  - tenant={t.tenant_id} user={t.user_id} "
            f"rows={total_rows} across {len(t.rows_by_table)} tables"
        )
    if seed_report.skipped:
        console.print(f"\n[yellow]Skipped {len(seed_report.skipped)} table(s):[/yellow]")
        for qualified, reason in seed_report.skipped:
            console.print(f"  - {qualified}: {reason}")
    if seed_report.check_warnings:
        console.print(
            f"\n[yellow]Note:[/yellow] {len(seed_report.check_warnings)} table(s) carry CHECK "
            "constraints — synthetic values may violate them. Add domain-specific seed code if "
            "coverage matters for these tables:"
        )
        for qualified in seed_report.check_warnings:
            console.print(f"  - {qualified}")


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--tenants", default=3, show_default=True, type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
@click.option(
    "--state-out",
    "state_out",
    default=None,
    help="Persist seeded tenant state to a JSON file (use with `rlsgrid teardown`).",
)
@click.option(
    "--shields-out",
    "shields_out",
    default=None,
    help="Write a shields.io endpoint JSON badge to PATH after the run.",
)
@click.option(
    "--badge-out",
    "badge_out",
    default=None,
    help="Write a static SVG badge to PATH after the run.",
)
def fuzz(
    config_path: str,
    tenants: int,
    as_json: bool,
    state_out: str | None,
    shields_out: str | None,
    badge_out: str | None,
) -> None:
    """Seed N tenants and run cross-tenant chaos. Exit 1 on any breach."""
    cfg = _load(config_path)
    _guard_writes(cfg)
    result = run_introspect(cfg)
    seed_report = seed_tenants(result, cfg, tenants=tenants)
    if state_out:
        seed_report.write_state(state_out)
    if len(seed_report.tenants) < 2:
        msg = "Seeder produced fewer than 2 tenants — cannot fuzz."
        if as_json:
            _dump_json({"ok": False, "error": msg})
        else:
            console.print(f"[red]{msg}[/red]")
        sys.exit(2)

    report = chaos.run(result, cfg, seeded_tenants=seed_report.tenants)

    if shields_out or badge_out:
        badge = from_fuzz_report(
            ok=report.ok,
            breaches=len(report.breaches),
            skipped=report.skipped,
        )
        if shields_out:
            Path(shields_out).write_text(json.dumps(make_shields_json(badge), indent=2))
        if badge_out:
            Path(badge_out).write_text(make_svg(badge))

    if as_json:
        _dump_json(
            {
                "ok": report.ok,
                "iterations": report.iterations,
                "skipped": report.skipped,
                "breaches": [
                    {
                        "actor_role": b.actor_role,
                        "actor_tenant": b.actor_tenant,
                        "target_tenant": b.target_tenant,
                        "schema": b.schema,
                        "table": b.table,
                        "operation": b.operation,
                        "detail": b.detail,
                    }
                    for b in report.breaches
                ],
            }
        )
        sys.exit(0 if report.ok else 1)

    if report.ok:
        console.print(
            f"[green]✓ No breaches[/green] in {report.iterations} iterations "
            f"({report.skipped} skipped)."
        )
        return

    console.print(f"[red]✗ {len(report.breaches)} breach(es) detected[/red]")
    for b in report.breaches:
        console.print(
            f"  [red]LEAK[/red] role={b.actor_role} actor_tenant={b.actor_tenant} "
            f"→ target_tenant={b.target_tenant} on {b.schema}.{b.table} {b.operation}: "
            f"{b.detail}"
        )
    sys.exit(1)


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--state", "state_path", required=True, help="Seed-state JSON written by `rlsgrid seed --state-out`.")
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
def teardown(config_path: str, state_path: str, as_json: bool) -> None:
    """Delete rows seeded earlier (idempotent — safe to run twice)."""
    cfg = _load(config_path)
    _guard_writes(cfg)
    report = teardown_from_state(state_path, cfg)

    if as_json:
        _dump_json(
            {
                "total_deleted": report.total_deleted,
                "deleted": report.deleted,
                "errors": report.errors,
            }
        )
        return

    if report.errors:
        console.print(f"[red]{len(report.errors)} table(s) failed teardown:[/red]")
        for qualified, err in report.errors.items():
            console.print(f"  - {qualified}: {err}")
    console.print(
        f"[green]✓[/green] Deleted {report.total_deleted} row(s) across "
        f"{len(report.deleted)} table(s)."
    )
    for qualified, n in sorted(report.deleted.items()):
        console.print(f"  - {qualified}: {n}")


if __name__ == "__main__":
    main()
