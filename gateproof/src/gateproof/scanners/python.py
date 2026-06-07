from pathlib import Path

from gateproof.scanners.common import (
    ensure_json_file,
    ensure_tool_available,
    run_command,
)


def run_bandit(source: Path, reports_dir: Path) -> Path:
    ensure_tool_available("bandit")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "bandit-report.json"

    run_command(
        [
            "bandit",
            "-r",
            str(source),
            "-f",
            "json",
            "-o",
            str(report_path),
        ],
        allow_failure=True,
    )
    ensure_json_file(report_path, '{"results":[]}')

    return report_path


def run_pip_audit(
    source: Path,
    reports_dir: Path,
    requirements_files: list[Path] | None = None,
) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    discovered_files = (
        requirements_files
        if requirements_files is not None
        else _find_requirements_files(source)
    )

    if not discovered_files:
        report_path = reports_dir / "pip-audit-report.json"
        ensure_json_file(report_path, '{"dependencies":[]}')
        return [report_path]

    ensure_tool_available("pip-audit")
    report_paths: list[Path] = []
    for index, requirements_file in enumerate(discovered_files, start=1):
        report_path = _pip_audit_report_path(
            reports_dir,
            use_index=len(discovered_files) > 1,
            index=index,
        )
        run_command(
            [
                "pip-audit",
                "-r",
                str(requirements_file),
                "-f",
                "json",
                "-o",
                str(report_path),
            ],
            allow_failure=True,
        )
        ensure_json_file(report_path, '{"dependencies":[]}')
        report_paths.append(report_path)

    return report_paths


def run_python_scanners(
    source: Path,
    reports_dir: Path,
    requirements_files: list[Path] | None = None,
) -> list[Path]:
    report_paths = [run_bandit(source, reports_dir)]
    report_paths.extend(run_pip_audit(source, reports_dir, requirements_files))
    return report_paths


def _find_requirements_files(source: Path) -> list[Path]:
    candidates = [
        source / "requirements.txt",
        source / "requirements" / "prod.txt",
        source / "requirements" / "base.txt",
    ]

    return [candidate for candidate in candidates if candidate.exists()]


def _pip_audit_report_path(reports_dir: Path, *, use_index: bool, index: int) -> Path:
    if not use_index:
        return reports_dir / "pip-audit-report.json"
    return reports_dir / f"pip-audit-report-{index}.json"
