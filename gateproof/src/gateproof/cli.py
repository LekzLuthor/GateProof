from pathlib import Path
from typing import Annotated

import typer

from gateproof.adapters.loader import load_reports_from_dir
from gateproof.adapters.mock import load_mock_report
from gateproof.evidence import build_evidence_bundle, write_json
from gateproof.models import GateStatus
from gateproof.policy_engine import evaluate_policy, load_policy
from gateproof.reporting import generate_html_report

app = typer.Typer(help="GateProof Security Gate CLI", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Evaluate security policies and produce evidence bundles."""


@app.command()
def evaluate(
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to a GateProof policy YAML file.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            file_okay=False,
            dir_okay=True,
            help="Directory where GateProof evidence artifacts are written.",
        ),
    ],
    commit: Annotated[
        str | None,
        typer.Option(
            "--commit",
            help="Commit SHA associated with this gate decision.",
        ),
    ] = None,
    mock_report: Annotated[
        Path | None,
        typer.Option(
            "--mock-report",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to a mock normalized scan report JSON file.",
        ),
    ] = None,
    reports: Annotated[
        Path | None,
        typer.Option(
            "--reports",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Directory with JSON security reports.",
        ),
    ] = None,
) -> None:
    if (mock_report is None) == (reports is None):
        raise typer.BadParameter(
            "Specify exactly one input mode: --mock-report or --reports."
        )

    loaded_policy = load_policy(policy)
    scan_reports = (
        [load_mock_report(mock_report)]
        if mock_report is not None
        else load_reports_from_dir(reports)
    )
    decision = evaluate_policy(loaded_policy, scan_reports, commit_sha=commit)
    manifest = build_evidence_bundle(output, policy, scan_reports, decision)
    generate_html_report(output, decision, manifest)
    write_json(output / "evidence-manifest.json", manifest)

    typer.echo(f"{decision.status.value}: {decision.explanation}")
    raise typer.Exit(code=0 if decision.status == GateStatus.PASS else 1)


if __name__ == "__main__":
    app()
