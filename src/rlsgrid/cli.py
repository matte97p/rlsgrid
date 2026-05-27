"""rlsgrid CLI — `rlsgrid <command>`."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import click
import psycopg
from rich.console import Console
from rich.table import Table

from . import __version__
from .autodetect import detect, render_config
from .badge import from_fuzz_report, make_shields_json, make_svg
from .config import DEFAULT_CONFIG_TEMPLATE, Config
from .emitters import pgtap as pgtap_emitter
from .fixtures import build_seed_plan, seed_tenants, teardown_from_state, teardown_state
from .fuzz import chaos
from .introspect import introspect as run_introspect
from .matrix import Expected, build_matrix, summarize
from .safety import ProdGuardViolation, assert_safe_to_write
from .sarif import build_sarif

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


def _introspect(cfg: Config):
    """Run introspection, turning connection failures into a clean message."""
    try:
        return run_introspect(cfg)
    except psycopg.OperationalError as exc:
        first = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        console.print(f"[red]Cannot connect to the database:[/red] {first}")
        console.print("Check [bold]connection.url[/bold] (or the env var it points at) in your config.")
        sys.exit(4)


def _run_writes(fn, *args, **kwargs):
    """Wrap a write-capable operation, mapping connection errors to exit 4."""
    try:
        return fn(*args, **kwargs)
    except psycopg.OperationalError as exc:
        first = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        console.print(f"[red]Cannot connect to the database:[/red] {first}")
        console.print("Check [bold]connection.url[/bold] (or the env var it points at) in your config.")
        sys.exit(4)


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
@click.option(
    "--from-db",
    "from_db",
    is_flag=True,
    help="Connect to DATABASE_URL, introspect the schema, and pre-fill the config.",
)
@click.option(
    "--config",
    "probe_config",
    default=None,
    help="Existing config to read connection.url from when using --from-db (optional).",
)
def init(out_path: str, force: bool, from_db: bool, probe_config: str | None) -> None:
    """Write a starter rlsgrid.toml (optionally auto-filled from the database)."""
    path = Path(out_path)
    if path.exists() and not force:
        console.print(f"[yellow]{path} already exists.[/yellow] Pass --force to overwrite.")
        sys.exit(1)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    if not from_db:
        path.write_text(DEFAULT_CONFIG_TEMPLATE)
        console.print(f"[green]✓[/green] Wrote {path}")
        return

    # Build a throwaway config pointing at the DB to introspect it.
    if probe_config and Path(probe_config).exists():
        cfg = Config.load(probe_config)
    else:
        import os

        url = os.environ.get("DATABASE_URL")
        if not url:
            console.print("[red]--from-db needs DATABASE_URL set (or --config pointing at a config with one).[/red]")
            sys.exit(2)
        from .config import ConnectionConfig

        cfg = Config(connection=ConnectionConfig(url=url))

    result = _introspect(cfg)
    detection = detect(result)
    path.write_text(render_config(detection))
    console.print(f"[green]✓[/green] Wrote {path} from live schema. Review the detection notes:")
    for note in detection.notes:
        console.print(f"  [dim]- {note}[/dim]")


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
def introspect(config_path: str, as_json: bool) -> None:
    """Print a summary of tables, RLS state, and policies."""
    cfg = _load(config_path)
    result = _introspect(cfg)

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
@click.option("--explain", is_flag=True, help="Add a column explaining why each cell got its label.")
def plan(config_path: str, show: str, as_json: bool, explain: bool) -> None:
    """Print the role × table × op matrix and expected outcomes."""
    cfg = _load(config_path)
    result = _introspect(cfg)
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
                        "reason": c.reason,
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
    if explain:
        table.add_column("Why", overflow="fold")

    for cell in visible:
        color = {
            Expected.ALLOW: "green",
            Expected.DENY: "red",
            Expected.CONDITIONAL: "yellow",
            Expected.UNRESTRICTED: "magenta",
        }[cell.expected]
        row = [
            cell.role,
            cell.qualified_table,
            cell.operation,
            f"[{color}]{cell.expected.value}[/{color}]",
            ", ".join(cell.applicable_policies) or "—",
        ]
        if explain:
            row.append(f"[dim]{cell.reason}[/dim]")
        table.add_row(*row)
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
    result = _introspect(cfg)
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
        introspection=result,
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
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    help="Show the seed plan (tables, order, detected root) without writing anything.",
)
def seed(config_path: str, tenants: int, as_json: bool, state_out: str | None, dry_run: bool) -> None:
    """Seed N synthetic tenants into every RLS table carrying tenant_column."""
    cfg = _load(config_path)
    result = _introspect(cfg)

    if dry_run:
        plan = build_seed_plan(result, cfg)
        if as_json:
            _dump_json(
                {
                    "tenant_column": plan.tenant_column,
                    "tenant_root": list(plan.tenant_root) if plan.tenant_root else None,
                    "order": [t.qualified for t in plan.ordered_tables],
                }
            )
            return
        console.print(f"[bold]Seed plan[/bold] (tenant_column = '{plan.tenant_column}')")
        if plan.tenant_root:
            s, t, c = plan.tenant_root
            console.print(f"  root table: [green]{s}.{t}[/green] keyed on '{c}' (seeded first)")
        else:
            console.print(
                "  [yellow]no tenant root table found — tenant_column is not a foreign key; "
                "verify it is correct[/yellow]"
            )
        if not plan.ordered_tables:
            console.print(
                "  [red]nothing to seed: no RLS table carries this tenant_column.[/red]"
            )
        for i, table in enumerate(plan.ordered_tables, 1):
            console.print(f"  {i}. {table.qualified}")
        return

    _guard_writes(cfg)
    seed_report = _run_writes(seed_tenants, result, cfg, tenants=tenants)
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
@click.option(
    "--cleanup/--no-cleanup",
    "cleanup",
    default=True,
    show_default=True,
    help="Delete the synthetic tenants this run seeded once it finishes.",
)
@click.option(
    "--sarif-out",
    "sarif_out",
    default=None,
    help="Write a SARIF 2.1.0 report to PATH (for GitHub code scanning).",
)
def fuzz(
    config_path: str,
    tenants: int,
    as_json: bool,
    state_out: str | None,
    shields_out: str | None,
    badge_out: str | None,
    cleanup: bool,
    sarif_out: str | None,
) -> None:
    """Seed N tenants and run cross-tenant chaos. Exit 1 on any breach."""
    cfg = _load(config_path)
    _guard_writes(cfg)
    result = _introspect(cfg)
    seed_report = _run_writes(seed_tenants, result, cfg, tenants=tenants)
    if state_out:
        seed_report.write_state(state_out)
    if not as_json:
        _warn_if_no_rows(seed_report, cfg)
    if len(seed_report.tenants) < 2:
        msg = "Seeder produced fewer than 2 tenants — cannot fuzz."
        if as_json:
            _dump_json({"ok": False, "error": msg})
        else:
            console.print(f"[red]{msg}[/red]")
        if cleanup:
            teardown_state(seed_report.to_state(), cfg)
        sys.exit(2)

    report = _run_writes(chaos.run, result, cfg, seeded_tenants=seed_report.tenants)

    if cleanup:
        _run_writes(teardown_state, seed_report.to_state(), cfg)

    if sarif_out:
        Path(sarif_out).write_text(json.dumps(build_sarif(report.breaches, version=__version__), indent=2))

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
                "skip_reasons": dict(report.skip_reasons),
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
        _print_skip_reasons(report)
        return

    console.print(f"[red]✗ {len(report.breaches)} breach(es) detected[/red]")
    for b in report.breaches:
        console.print(
            f"  [red]LEAK[/red] role={b.actor_role} actor_tenant={b.actor_tenant} "
            f"→ target_tenant={b.target_tenant} on {b.schema}.{b.table} {b.operation}: "
            f"{b.detail}"
        )
    _print_skip_reasons(report)
    sys.exit(1)


def _print_skip_reasons(report: chaos.FuzzReport) -> None:
    if not report.skip_reasons:
        return
    console.print("[dim]Skipped probe reasons:[/dim]")
    for reason, count in report.skip_reasons.most_common():
        console.print(f"  [dim]- {reason}: {count}[/dim]")


def _warn_if_no_rows(seed_report, cfg: Config) -> bool:
    """Loudly warn when seeding produced nothing — a wrong tenant_column makes
    every probe vacuous and the run reports a misleading 'no breach'.

    Returns True if the warning fired.
    """
    total = sum(len(rs) for t in seed_report.tenants for rs in t.rows_by_table.values())
    if total > 0:
        return False
    console.print(
        "[bold red]⚠ No rows were seeded.[/bold red] "
        f"tenant_column='[bold]{cfg.tenancy.tenant_column}[/bold]' likely does not match your "
        "schema, so every cross-tenant probe is vacuous and results are NOT trustworthy."
    )
    if seed_report.skipped:
        console.print("Seeder skip reasons:")
        for qualified, reason in seed_report.skipped:
            console.print(f"  - {qualified}: {reason}")
    console.print(
        "Fix [bold]tenancy.tenant_column[/bold] in your config "
        "(or re-run [bold]rlsgrid init --from-db[/bold]) and try again."
    )
    return True


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--state", "state_path", required=True, help="Seed-state JSON written by `rlsgrid seed --state-out`.")
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
def teardown(config_path: str, state_path: str, as_json: bool) -> None:
    """Delete rows seeded earlier (idempotent — safe to run twice)."""
    cfg = _load(config_path)
    _guard_writes(cfg)
    report = _run_writes(teardown_from_state, state_path, cfg)

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


@main.command()
@click.option("--config", "config_path", default="rlsgrid.toml", show_default=True)
@click.option("--tenants", default=3, show_default=True, type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON document instead of a table.")
@click.option(
    "--sarif-out",
    "sarif_out",
    default=None,
    help="Write a SARIF 2.1.0 report to PATH (for GitHub code scanning).",
)
def check(config_path: str, tenants: int, as_json: bool, sarif_out: str | None) -> None:
    """One-shot safety check: seed, fuzz, tear down. Exit 1 on any breach.

    The headline command — no state files, nothing left behind. Ideal for a
    first run or a CI gate.
    """
    cfg = _load(config_path)
    _guard_writes(cfg)
    result = _introspect(cfg)
    seed_report = _run_writes(seed_tenants, result, cfg, tenants=tenants)
    try:
        if not as_json:
            _warn_if_no_rows(seed_report, cfg)
        if len(seed_report.tenants) < 2:
            msg = "Seeder produced fewer than 2 tenants — cannot run cross-tenant checks."
            if as_json:
                _dump_json({"ok": False, "error": msg})
            else:
                console.print(f"[red]{msg}[/red]")
            sys.exit(2)
        report = _run_writes(chaos.run, result, cfg, seeded_tenants=seed_report.tenants)
    finally:
        _run_writes(teardown_state, seed_report.to_state(), cfg)

    if sarif_out:
        Path(sarif_out).write_text(json.dumps(build_sarif(report.breaches, version=__version__), indent=2))

    if as_json:
        _dump_json(
            {
                "ok": report.ok,
                "iterations": report.iterations,
                "skipped": report.skipped,
                "skip_reasons": dict(report.skip_reasons),
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
            f"[green]✓ Safe[/green] — no cross-tenant breaches in "
            f"{report.iterations} iterations ({report.skipped} skipped)."
        )
        _print_skip_reasons(report)
        return

    console.print(f"[red]✗ {len(report.breaches)} cross-tenant breach(es) detected[/red]")
    for b in report.breaches:
        console.print(
            f"  [red]LEAK[/red] role={b.actor_role} actor_tenant={b.actor_tenant} "
            f"→ target_tenant={b.target_tenant} on {b.schema}.{b.table} {b.operation}: "
            f"{b.detail}"
        )
    _print_skip_reasons(report)
    sys.exit(1)


if __name__ == "__main__":
    main()
