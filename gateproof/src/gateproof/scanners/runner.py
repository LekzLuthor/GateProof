from enum import StrEnum
from pathlib import Path

from gateproof.scanners.common import (
    ScannerExecutionError,
    ensure_json_file,
    ensure_tool_available,
    run_command,
)
from gateproof.scanners.python import run_python_scanners


class ProjectLanguage(StrEnum):
    PYTHON = "python"
    GO = "go"
    CPP = "cpp"
    AUTO = "auto"


def detect_language(source: Path) -> ProjectLanguage:
    if (
        (source / "requirements.txt").exists()
        or (source / "pyproject.toml").exists()
        or _app_dir_has_python_files(source)
    ):
        return ProjectLanguage.PYTHON

    if (source / "go.mod").exists():
        return ProjectLanguage.GO

    if (
        (source / "CMakeLists.txt").exists()
        or (source / "conanfile.txt").exists()
        or (source / "conanfile.py").exists()
        or _has_cpp_files(source)
    ):
        return ProjectLanguage.CPP

    return ProjectLanguage.PYTHON


def run_scanners(
    *,
    source: Path,
    reports_dir: Path,
    language: ProjectLanguage,
    image: str | None = None,
    gitleaks_config: Path | None = None,
    include_container: bool = True,
) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    selected_language = (
        detect_language(source)
        if language == ProjectLanguage.AUTO
        else language
    )

    if selected_language in {ProjectLanguage.GO, ProjectLanguage.CPP}:
        raise ScannerExecutionError(
            f"Language '{selected_language.value}' is detected but scanner "
            "profile is not implemented yet."
        )

    report_paths: list[Path] = []
    if selected_language == ProjectLanguage.PYTHON:
        report_paths.extend(run_python_scanners(source, reports_dir))

    report_paths.append(run_gitleaks(source, reports_dir, config=gitleaks_config))

    if image is not None and include_container:
        report_paths.append(run_trivy_image(image, reports_dir))

    return report_paths


def run_gitleaks(
    source: Path,
    reports_dir: Path,
    config: Path | None = None,
) -> Path:
    ensure_tool_available("gitleaks")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "gitleaks-report.json"

    command = [
        "gitleaks",
        "detect",
        "--source",
        str(source),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-git",
    ]
    if config is not None:
        command[4:4] = ["--config", str(config)]

    run_command(command, allow_failure=True)
    ensure_json_file(report_path, "[]")

    return report_path


def run_trivy_image(image: str, reports_dir: Path) -> Path:
    ensure_tool_available("trivy")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "trivy-report.json"

    run_command(
        [
            "trivy",
            "image",
            "--format",
            "json",
            "--output",
            str(report_path),
            image,
        ],
        allow_failure=True,
    )
    ensure_json_file(report_path, '{"Results":[]}')

    return report_path


def _app_dir_has_python_files(source: Path) -> bool:
    app_dir = source / "app"
    return app_dir.exists() and any(app_dir.rglob("*.py"))


def _has_cpp_files(source: Path) -> bool:
    cpp_suffixes = {".cpp", ".hpp", ".c", ".h"}
    return any(path.suffix in cpp_suffixes for path in source.rglob("*"))
