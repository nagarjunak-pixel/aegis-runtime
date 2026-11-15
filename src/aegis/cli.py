"""Command-line interface (`aegis`) for benchmarks, red-teaming, demos, and serving."""

from __future__ import annotations

import asyncio
import json

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis.api.app import create_app
from aegis.benchmarks.chaos_suite import run_chaos_benchmark
from aegis.benchmarks.redteam_suite import run_redteam_suite
from aegis.enterprise.scenarios import EnterpriseScenarioCatalog
from aegis.runtime import AegisRuntime

app = typer.Typer(
    name="aegis",
    help="AegisRuntime — Zero-Trust Enterprise Agentic Control Plane & Transactional Saga Engine",
    add_completion=False,
)
console = Console()


@app.command()
def demo() -> None:
    """Execute all 6 Fortune-500 Enterprise ERP & Governance scenarios and verify invariants."""

    async def _run() -> None:
        rt = AegisRuntime()
        table = Table(title="AegisRuntime — Fortune-500 Enterprise Reference Scenarios")
        table.add_column("Scenario", style="cyan", no_wrap=True)
        table.add_column("Model Routed", style="magenta")
        table.add_column("Saga Terminal Status", style="bold")
        table.add_column("Compensated", justify="right")
        table.add_column("Latency (ms)", justify="right")
        table.add_column("ERP Invariants", justify="center")

        for desc in EnterpriseScenarioCatalog.list_scenarios():
            bundle = await rt.run_reference_scenario(desc.scenario_id)
            st = bundle.saga_result.status.value
            color = (
                "green"
                if st == "COMMITTED"
                else ("yellow" if st in ("COMPENSATED", "BLOCKED_BY_POLICY") else "red")
            )
            table.add_row(
                desc.scenario_id,
                bundle.routing.selected_model_id,
                f"[{color}]{st}[/{color}]",
                str(bundle.saga_result.compensated_steps),
                f"{bundle.saga_result.total_latency_ms:.2f}",
                "[green]PASS[/green]" if bundle.conservation_passed else "[red]FAIL[/red]",
            )

        chain = rt.ledger.verify_chain_integrity()
        console.print(table)
        console.print(
            Panel(
                f"[bold green]Cryptographic Ledger Audit:[/bold green] VALID={chain.valid} | "
                f"Events={chain.events_checked} | RFC-6962 Merkle Root=[cyan]{chain.merkle_root[:32]}...[/cyan]\n"
                f"[bold green]Ed25519 Public Key:[/bold green] {rt.ledger.signer.public_key_hex}",
                title="Zero-Trust Attestation Summary",
            )
        )

    asyncio.run(_run())


@app.command()
def benchmark(
    transactions: int = typer.Option(200, help="Number of multi-step ERP sagas to execute"),
    fault_rate: float = typer.Option(0.25, help="Downstream chaos fault probability [0.0..0.9]"),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
) -> None:
    """Run Chaos Fault-Injection Benchmark and verify zero orphaned ERP transactions."""
    report = asyncio.run(run_chaos_benchmark(transactions=transactions, fault_rate=fault_rate))
    if json_out:
        console.print_json(json.dumps(report.model_dump()))
        return

    tbl = Table(
        title=f"Chaos & Saga Conservation Benchmark ({transactions} Sagas @ {fault_rate:.0%} Fault Rate)"
    )
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Measured Value", style="bold white", justify="right")

    tbl.add_row("Committed Sagas", str(report.committed_sagas))
    tbl.add_row("Compensated (Rolled Back) Sagas", str(report.compensated_sagas))
    tbl.add_row("Blocked by Policy Gatekeeper", str(report.blocked_sagas))
    tbl.add_row("Quarantined Sagas", str(report.quarantined_sagas))
    tbl.add_row(
        "Orphan ERP/Treasury Mutations", f"[bold green]{report.orphan_mutations}[/bold green]"
    )
    tbl.add_row(
        "Double-Entry Conservation Law",
        "[bold green]VERIFIED[/bold green]"
        if report.conservation_invariants_passed
        else "[red]FAILED[/red]",
    )
    tbl.add_row(
        "SHA-256 + Ed25519 Ledger Audit",
        f"[bold green]VERIFIED ({report.ledger_events_verified} events)[/bold green]",
    )
    tbl.add_row(
        "AST Policy Eval Latency (p50 / p95 / p99)",
        f"{report.policy_eval_p50_us:.1f} µs / {report.policy_eval_p95_us:.1f} µs / {report.policy_eval_p99_us:.1f} µs",
    )
    tbl.add_row(
        "End-to-End Saga Latency (p50 / p95 / p99)",
        f"{report.saga_latency_p50_ms:.2f} ms / {report.saga_latency_p95_ms:.2f} ms / {report.saga_latency_p99_ms:.2f} ms",
    )
    tbl.add_row("Control-Plane Throughput", f"{report.throughput_sagas_per_sec:.1f} sagas/sec")
    tbl.add_row("RFC-6962 Merkle Root", f"{report.merkle_root[:28]}...")
    console.print(tbl)

    if not report.conservation_invariants_passed or not report.ledger_integrity_passed:
        raise typer.Exit(code=1)


@app.command()
def redteam(
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
) -> None:
    """Execute 12-vector OWASP LLM / SOX / OFAC Adversarial Red-Team Suite."""
    report = asyncio.run(run_redteam_suite())
    if json_out:
        console.print_json(json.dumps(report.model_dump()))
        return

    tbl = Table(title="AegisRuntime — 12-Vector Adversarial Red-Team Containment Matrix")
    tbl.add_column("ID", style="cyan", no_wrap=True)
    tbl.add_column("Category", style="magenta")
    tbl.add_column("Adversarial Vector")
    tbl.add_column("Defense Layer", style="blue")
    tbl.add_column("Verdict", justify="center")

    for r in report.results:
        badge = (
            "[bold green]CONTAINED[/bold green]" if r.contained else "[bold red]BREACHED[/bold red]"
        )
        tbl.add_row(r.attack_id, r.category, r.title, r.defense_layer, badge)

    console.print(tbl)
    console.print(
        f"\n[bold]Containment Rate:[/bold] {report.contained_attacks}/{report.total_attacks} "
        f"([bold green]{report.containment_rate_pct:.1f}%[/bold green])"
    )
    if not report.all_contained:
        raise typer.Exit(code=1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address"),
    port: int = typer.Option(8000, help="Bind port"),
    db_path: str = typer.Option(".aegis_data/ledger.db", help="SQLite WAL ledger file path"),
) -> None:
    """Launch the AegisRuntime Control Plane API & Live Operator Control Tower UI."""
    rt = AegisRuntime(db_path=db_path)
    fastapi_app = create_app(rt)
    console.print(
        Panel(
            f"[bold cyan]AegisRuntime Control Plane[/bold cyan] listening on [underline]http://{host}:{port}[/underline]\n"
            f"• REST OpenAPI Docs: http://{host}:{port}/docs\n"
            f"• Prometheus Metrics: http://{host}:{port}/metrics\n"
            f"• SQLite WAL Ledger: {db_path}",
            title="AegisRuntime v0.4.0",
        )
    )
    uvicorn.run(fastapi_app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
