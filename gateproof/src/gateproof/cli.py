from pathlib import Path
from typing import Annotated

import typer

from gateproof.adapters.loader import load_reports_from_dir
from gateproof.adapters.mock import load_mock_report
from gateproof.evidence import build_evidence_bundle, write_json
from gateproof.models import GateDecision, GateStatus, ScanReport
from gateproof.policy_engine import evaluate_policy, load_policy
from gateproof.reporting import generate_html_report
from gateproof.scanners.common import ScannerExecutionError
from gateproof.scanners.runner import ProjectLanguage, run_scanners

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

    decision = (
        _evaluate_scan_reports(
            policy_path=policy,
            scan_reports=[load_mock_report(mock_report)],
            output=output,
            commit=commit,
        )
        if mock_report is not None
        else _evaluate_reports(
            policy_path=policy,
            reports_dir=reports,
            output=output,
            commit=commit,
        )
    )

    typer.echo(f"{decision.status.value}: {decision.explanation}")
    raise typer.Exit(code=0 if decision.status == GateStatus.PASS else 1)


@app.command()
def scan(
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
    source: Annotated[
        Path,
        typer.Option(
            "--source",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Project source directory to scan.",
        ),
    ] = Path("."),
    language: Annotated[
        str,
        typer.Option(
            "--language",
            help="Project language: auto, python, go, or cpp.",
        ),
    ] = "auto",
    image: Annotated[
        str | None,
        typer.Option(
            "--image",
            help="Container image name to scan with Trivy.",
        ),
    ] = None,
    reports: Annotated[
        Path,
        typer.Option(
            "--reports",
            file_okay=False,
            dir_okay=True,
            help="Directory where scanner JSON reports are written.",
        ),
    ] = Path(".gateproof/input"),
    commit: Annotated[
        str | None,
        typer.Option(
            "--commit",
            help="Commit SHA associated with this gate decision.",
        ),
    ] = None,
    gitleaks_config: Annotated[
        Path | None,
        typer.Option(
            "--gitleaks-config",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Optional Gitleaks config path.",
        ),
    ] = None,
    no_container: Annotated[
        bool,
        typer.Option(
            "--no-container",
            help="Skip Trivy container image scanning even when --image is set.",
        ),
    ] = False,
) -> None:
    project_language = _parse_project_language(language)

    try:
        run_scanners(
            source=source,
            reports_dir=reports,
            language=project_language,
            image=image,
            gitleaks_config=gitleaks_config,
            include_container=not no_container,
        )
    except ScannerExecutionError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=2) from error

    decision = _evaluate_reports(
        policy_path=policy,
        reports_dir=reports,
        output=output,
        commit=commit,
    )

    typer.echo(f"{decision.status.value}: {decision.explanation}")
    raise typer.Exit(code=0 if decision.status == GateStatus.PASS else 1)


def _evaluate_reports(
    policy_path: Path,
    reports_dir: Path,
    output: Path,
    commit: str | None,
) -> GateDecision:
    return _evaluate_scan_reports(
        policy_path=policy_path,
        scan_reports=load_reports_from_dir(reports_dir),
        output=output,
        commit=commit,
    )


def _evaluate_scan_reports(
    policy_path: Path,
    scan_reports: list[ScanReport],
    output: Path,
    commit: str | None,
) -> GateDecision:
    loaded_policy = load_policy(policy_path)
    decision = evaluate_policy(loaded_policy, scan_reports, commit_sha=commit)
    manifest = build_evidence_bundle(output, policy_path, scan_reports, decision)
    generate_html_report(output, decision, manifest)
    write_json(output / "evidence-manifest.json", manifest)

    return decision


def _parse_project_language(language: str) -> ProjectLanguage:
    try:
        return ProjectLanguage(language.lower())
    except ValueError as error:
        valid_languages = ", ".join(item.value for item in ProjectLanguage)
        raise typer.BadParameter(
            f"Unsupported language '{language}'. Expected one of: "
            f"{valid_languages}."
        ) from error


if __name__ == "__main__":
    app()
