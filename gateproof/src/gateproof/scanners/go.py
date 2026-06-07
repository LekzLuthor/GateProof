from pathlib import Path

from gateproof.scanners.common import (
    ensure_json_file,
    ensure_tool_available,
    run_command,
)


def run_gosec(
    source: Path,
    reports_dir: Path,
    packages: list[str] | None = None,
) -> Path:
    ensure_tool_available("gosec")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "gosec-report.json"
    selected_packages = packages or ["./..."]

    run_command(
        [
            "gosec",
            "-fmt=json",
            f"-out={report_path.resolve()}",
            *selected_packages,
        ],
        cwd=source,
        allow_failure=True,
    )
    ensure_json_file(report_path, '{"Issues":[]}')

    return report_path


def run_govulncheck(
    source: Path,
    reports_dir: Path,
    packages: list[str] | None = None,
) -> Path:
    ensure_tool_available("govulncheck")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "govulncheck-report.json"
    selected_packages = packages or ["./..."]

    completed = run_command(
        ["govulncheck", "-json", *selected_packages],
        cwd=source,
        allow_failure=True,
    )
    if completed.stdout:
        report_path.write_text(completed.stdout, encoding="utf-8")
    ensure_json_file(report_path, "[]")

    return report_path


def run_go_scanners(
    source: Path,
    reports_dir: Path,
    packages: list[str] | None = None,
) -> list[Path]:
    return [
        run_gosec(source, reports_dir, packages),
        run_govulncheck(source, reports_dir, packages),
    ]

