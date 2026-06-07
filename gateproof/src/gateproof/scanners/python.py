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


def run_pip_audit(source: Path, reports_dir: Path) -> Path:
    ensure_tool_available("pip-audit")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "pip-audit-report.json"
    requirements_file = _find_requirements_file(source)

    if requirements_file is None:
        ensure_json_file(report_path, '{"dependencies":[]}')
        return report_path

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

    return report_path


def run_python_scanners(source: Path, reports_dir: Path) -> list[Path]:
    return [
        run_bandit(source, reports_dir),
        run_pip_audit(source, reports_dir),
    ]


def _find_requirements_file(source: Path) -> Path | None:
    candidates = [
        source / "requirements.txt",
        source / "requirements" / "prod.txt",
        source / "requirements" / "base.txt",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None

