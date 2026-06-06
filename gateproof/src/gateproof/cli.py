from pathlib import Path

import typer

from gateproof.adapters.mock import load_mock_report
from gateproof.evidence import build_evidence_bundle
from gateproof.models import GateStatus
from gateproof.policy_engine import evaluate_policy, load_policy

app = typer.Typer(help="GateProof Security Gate CLI", no_args_is_help=True)


@app.callback()
def main() -> None:
    """Evaluate security policies and produce evidence bundles."""


@app.command()
def evaluate(
    policy: Path = typer.Option(
        ...,
        "--policy",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a GateProof policy YAML file.",
    ),
    mock_report: Path = typer.Option(
        ...,
        "--mock-report",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a mock normalized scan report JSON file.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        file_okay=False,
        dir_okay=True,
        help="Directory where GateProof evidence artifacts are written.",
    ),
    commit: str | None = typer.Option(
        None,
        "--commit",
        help="Commit SHA associated with this gate decision.",
    ),
) -> None:
    loaded_policy = load_policy(policy)
    report = load_mock_report(mock_report)
    decision = evaluate_policy(loaded_policy, [report], commit_sha=commit)
    build_evidence_bundle(output, policy, [report], decision)

    typer.echo(f"{decision.status.value}: {decision.explanation}")
    raise typer.Exit(code=0 if decision.status == GateStatus.PASS else 1)


if __name__ == "__main__":
    app()
