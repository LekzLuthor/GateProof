from enum import StrEnum
from pathlib import Path

from gateproof.scanners.common import (
    ScannerExecutionError,
    ensure_json_file,
    ensure_tool_available,
    run_command,
)
from gateproof.scanners.go import run_go_scanners
from gateproof.scanners.python import run_python_scanners


class ProjectLanguage(StrEnum):
    PYTHON = "python"
    GO = "go"
    CPP = "cpp"
    AUTO = "auto"


def detect_language(source: Path) -> ProjectLanguage:
    return detect_languages(source)[0]


def detect_languages(source: Path) -> list[ProjectLanguage]:
    detected: list[ProjectLanguage] = []

    if (
        (source / "requirements.txt").exists()
        or (source / "pyproject.toml").exists()
        or (source / "setup.py").exists()
        or (source / "setup.cfg").exists()
        or (source / "poetry.lock").exists()
        or _dir_has_python_files(source / "app")
        or _dir_has_python_files(source / "src")
    ):
        detected.append(ProjectLanguage.PYTHON)

    if (source / "go.mod").exists() or _has_files_with_suffixes(source, {".go"}):
        detected.append(ProjectLanguage.GO)

    if (
        (source / "CMakeLists.txt").exists()
        or (source / "conanfile.txt").exists()
        or (source / "conanfile.py").exists()
        or _has_files_with_suffixes(source, {".cpp", ".hpp", ".c", ".h"})
    ):
        detected.append(ProjectLanguage.CPP)

    return detected or [ProjectLanguage.PYTHON]


def parse_languages(value: str | None) -> list[ProjectLanguage]:
    if value is None or not value.strip():
        return [ProjectLanguage.AUTO]

    languages: list[ProjectLanguage] = []
    for raw_item in value.split(","):
        item = raw_item.strip().lower()
        if not item:
            continue
        try:
            language = ProjectLanguage(item)
        except ValueError as error:
            valid_languages = ", ".join(item.value for item in ProjectLanguage)
            raise ScannerExecutionError(
                f"Unsupported language '{item}'. Expected one of: "
                f"{valid_languages}."
            ) from error
        if language not in languages:
            languages.append(language)

    if not languages:
        return [ProjectLanguage.AUTO]

    if ProjectLanguage.AUTO in languages and len(languages) > 1:
        raise ScannerExecutionError(
            "Language 'auto' cannot be combined with explicit languages."
        )

    return languages


def run_scanners(
    *,
    source: Path,
    reports_dir: Path,
    languages: list[ProjectLanguage],
    image: str | None = None,
    gitleaks_config: Path | None = None,
    include_container: bool = True,
    python_source: Path | None = None,
    python_requirements: list[Path] | None = None,
    go_source: Path | None = None,
    go_packages: list[str] | None = None,
) -> list[Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    selected_languages = _resolve_languages(source, languages)

    report_paths: list[Path] = []
    for selected_language in selected_languages:
        if selected_language == ProjectLanguage.CPP:
            raise ScannerExecutionError(
                f"Language '{selected_language.value}' is detected but scanner "
                "profile is not implemented yet."
            )
        if selected_language == ProjectLanguage.PYTHON:
            report_paths.extend(
                run_python_scanners(
                    python_source or source,
                    reports_dir,
                    requirements_files=python_requirements,
                )
            )
        if selected_language == ProjectLanguage.GO:
            report_paths.extend(
                run_go_scanners(
                    go_source or source,
                    reports_dir,
                    packages=go_packages,
                )
            )

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


def _resolve_languages(
    source: Path,
    languages: list[ProjectLanguage],
) -> list[ProjectLanguage]:
    if ProjectLanguage.AUTO in languages and len(languages) > 1:
        raise ScannerExecutionError(
            "Language 'auto' cannot be combined with explicit languages."
        )
    if not languages or ProjectLanguage.AUTO in languages:
        return detect_languages(source)

    selected_languages: list[ProjectLanguage] = []
    for language in languages:
        if language not in selected_languages:
            selected_languages.append(language)
    return selected_languages


def _dir_has_python_files(path: Path) -> bool:
    return path.exists() and any(path.rglob("*.py"))


def _has_files_with_suffixes(source: Path, suffixes: set[str]) -> bool:
    return any(path.suffix in suffixes for path in source.rglob("*"))
