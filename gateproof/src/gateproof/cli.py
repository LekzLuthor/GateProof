from pathlib import Path
from typing import Annotated

import typer

from gateproof.adapters.loader import load_reports_from_dir
from gateproof.adapters.mock import load_mock_report
from gateproof.config import GateProofConfig, load_config
from gateproof.evidence import build_evidence_bundle, write_json
from gateproof.models import GateDecision, GateStatus, ScanReport
from gateproof.policy_engine import evaluate_policy, load_policy
from gateproof.reporting import generate_html_report
from gateproof.scanners.common import ScannerExecutionError
from gateproof.scanners.runner import ProjectLanguage, parse_languages, run_scanners

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
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Optional GateProof config YAML file.",
        ),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option(
            "--source",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Project source directory to scan.",
        ),
    ] = None,
    languages: Annotated[
        str | None,
        typer.Option(
            "--languages",
            help="Comma-separated project languages: auto, python, go, cpp.",
        ),
    ] = None,
    language: Annotated[
        str | None,
        typer.Option(
            "--language",
            help="Deprecated. Use --languages instead.",
        ),
    ] = None,
    image: Annotated[
        str | None,
        typer.Option(
            "--image",
            help="Container image name to scan with Trivy.",
        ),
    ] = None,
    reports: Annotated[
        Path | None,
        typer.Option(
            "--reports",
            file_okay=False,
            dir_okay=True,
            help="Directory where scanner JSON reports are written.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            file_okay=False,
            dir_okay=True,
            help="Directory where GateProof evidence artifacts are written.",
        ),
    ] = None,
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
    try:
        loaded_config = load_config(config) if config is not None else None
        scan_options = _resolve_scan_options(
            config=loaded_config,
            source=source,
            languages=languages,
            language=language,
            reports=reports,
            output=output,
            image=image,
            gitleaks_config=gitleaks_config,
            no_container=no_container,
        )
        run_scanners(
            source=scan_options.source,
            reports_dir=scan_options.reports,
            languages=scan_options.languages,
            image=scan_options.image,
            gitleaks_config=scan_options.gitleaks_config,
            include_container=scan_options.include_container,
            python_source=scan_options.python_source,
            python_requirements=scan_options.python_requirements,
            go_source=scan_options.go_source,
            go_packages=scan_options.go_packages,
        )
    except (ScannerExecutionError, ValueError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=2) from error

    decision = _evaluate_reports(
        policy_path=policy,
        reports_dir=scan_options.reports,
        output=scan_options.output,
        commit=commit,
    )

    typer.echo(f"{decision.status.value}: {decision.explanation}")
    raise typer.Exit(code=0 if decision.status == GateStatus.PASS else 1)


class _ScanOptions:
    def __init__(
        self,
        *,
        source: Path,
        languages: list[ProjectLanguage],
        reports: Path,
        output: Path,
        image: str | None,
        gitleaks_config: Path | None,
        include_container: bool,
        python_source: Path | None,
        python_requirements: list[Path] | None,
        go_source: Path | None,
        go_packages: list[str] | None,
    ) -> None:
        self.source = source
        self.languages = languages
        self.reports = reports
        self.output = output
        self.image = image
        self.gitleaks_config = gitleaks_config
        self.include_container = include_container
        self.python_source = python_source
        self.python_requirements = python_requirements
        self.go_source = go_source
        self.go_packages = go_packages


def _resolve_scan_options(
    *,
    config: GateProofConfig | None,
    source: Path | None,
    languages: str | None,
    language: str | None,
    reports: Path | None,
    output: Path | None,
    image: str | None,
    gitleaks_config: Path | None,
    no_container: bool,
) -> _ScanOptions:
    resolved_source = source or _config_source(config) or Path(".")
    if not resolved_source.exists():
        raise ValueError(f"Project source directory does not exist: {resolved_source}")

    resolved_languages = _resolve_languages(config, languages, language)
    resolved_reports = reports or _config_reports(config) or Path(".gateproof/input")
    resolved_output = output or _config_output(config) or Path(".gateproof/evidence")
    resolved_image = image or _config_image(config)
    resolved_gitleaks_config = gitleaks_config or _config_gitleaks_config(config)
    include_container = _resolve_include_container(config, no_container)

    python_source = _config_python_source(config)
    python_requirements = _config_python_requirements(config)
    go_source = _config_go_source(config)
    go_packages = _config_go_packages(config)

    return _ScanOptions(
        source=resolved_source,
        languages=resolved_languages,
        reports=resolved_reports,
        output=resolved_output,
        image=resolved_image,
        gitleaks_config=resolved_gitleaks_config,
        include_container=include_container,
        python_source=python_source,
        python_requirements=python_requirements,
        go_source=go_source,
        go_packages=go_packages,
    )


def _resolve_languages(
    config: GateProofConfig | None,
    languages: str | None,
    language: str | None,
) -> list[ProjectLanguage]:
    if languages is not None:
        return parse_languages(languages)
    if language is not None:
        return parse_languages(language)
    if config is not None:
        return parse_languages(",".join(config.scan.languages))
    return parse_languages(None)


def _resolve_include_container(
    config: GateProofConfig | None,
    no_container: bool,
) -> bool:
    if no_container:
        return False
    if config is not None and not config.scan.container.enabled:
        return False
    return True


def _config_source(config: GateProofConfig | None) -> Path | None:
    return config.scan.source if config is not None else None


def _config_reports(config: GateProofConfig | None) -> Path | None:
    return config.evidence.reports if config is not None else None


def _config_output(config: GateProofConfig | None) -> Path | None:
    return config.evidence.output if config is not None else None


def _config_image(config: GateProofConfig | None) -> str | None:
    return config.scan.container.image if config is not None else None


def _config_gitleaks_config(config: GateProofConfig | None) -> Path | None:
    return config.scan.common.gitleaks_config if config is not None else None


def _config_python_source(config: GateProofConfig | None) -> Path | None:
    return config.scan.python.source if config is not None else None


def _config_python_requirements(config: GateProofConfig | None) -> list[Path] | None:
    if config is None or not config.scan.python.requirements:
        return None
    return config.scan.python.requirements


def _config_go_source(config: GateProofConfig | None) -> Path | None:
    return config.scan.go.source if config is not None else None


def _config_go_packages(config: GateProofConfig | None) -> list[str] | None:
    if config is None or not config.scan.go.packages:
        return None
    return config.scan.go.packages


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


if __name__ == "__main__":
    app()
