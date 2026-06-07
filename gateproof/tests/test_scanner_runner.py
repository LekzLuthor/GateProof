from pathlib import Path

import pytest

from gateproof.scanners.common import ScannerExecutionError
from gateproof.scanners.runner import (
    ProjectLanguage,
    detect_language,
    detect_languages,
    parse_languages,
    run_scanners,
)


def test_detect_language_detects_python_by_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")

    assert detect_language(tmp_path) == ProjectLanguage.PYTHON
    assert detect_languages(tmp_path) == [ProjectLanguage.PYTHON]


def test_detect_language_detects_go_by_go_mod(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/demo\n", encoding="utf-8")

    assert detect_language(tmp_path) == ProjectLanguage.GO
    assert detect_languages(tmp_path) == [ProjectLanguage.GO]


def test_detect_languages_detects_python_and_go(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module example.com/demo\n", encoding="utf-8")

    assert detect_languages(tmp_path) == [
        ProjectLanguage.PYTHON,
        ProjectLanguage.GO,
    ]


def test_detect_language_detects_cpp_by_cmake(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n",
        encoding="utf-8",
    )

    assert detect_language(tmp_path) == ProjectLanguage.CPP
    assert detect_languages(tmp_path) == [ProjectLanguage.CPP]


def test_parse_languages_parses_comma_separated_values() -> None:
    assert parse_languages("python, go") == [
        ProjectLanguage.PYTHON,
        ProjectLanguage.GO,
    ]


def test_parse_languages_rejects_auto_with_explicit_language() -> None:
    with pytest.raises(
        ScannerExecutionError,
        match="Language 'auto' cannot be combined with explicit languages.",
    ):
        parse_languages("auto,python")


def test_parse_languages_rejects_unknown_language() -> None:
    with pytest.raises(ScannerExecutionError, match="Unsupported language 'bad'"):
        parse_languages("bad")


def test_run_scanners_runs_go_and_common_scanners(monkeypatch, tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    calls: list[tuple[str, object]] = []

    def fake_run_go_scanners(
        source: Path,
        reports_dir: Path,
        packages: list[str] | None = None,
    ) -> list[Path]:
        calls.append(("go", source, packages))
        report_path = reports_dir / "gosec-report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text('{"Issues":[]}', encoding="utf-8")
        return [report_path]

    def fake_run_gitleaks(
        source: Path,
        reports_dir: Path,
        config: Path | None = None,
    ) -> Path:
        del config
        calls.append(("gitleaks", source))
        report_path = reports_dir / "gitleaks-report.json"
        report_path.write_text("[]", encoding="utf-8")
        return report_path

    def fake_run_trivy_image(image: str, reports_dir: Path) -> Path:
        calls.append(("trivy", image))
        report_path = reports_dir / "trivy-report.json"
        report_path.write_text('{"Results":[]}', encoding="utf-8")
        return report_path

    monkeypatch.setattr(
        "gateproof.scanners.runner.run_go_scanners",
        fake_run_go_scanners,
    )
    monkeypatch.setattr("gateproof.scanners.runner.run_gitleaks", fake_run_gitleaks)
    monkeypatch.setattr(
        "gateproof.scanners.runner.run_trivy_image",
        fake_run_trivy_image,
    )

    report_paths = run_scanners(
        source=tmp_path,
        reports_dir=reports_dir,
        languages=[ProjectLanguage.GO],
        image="demo:latest",
        go_source=tmp_path,
        go_packages=["./..."],
    )

    assert calls == [
        ("go", tmp_path, ["./..."]),
        ("gitleaks", tmp_path),
        ("trivy", "demo:latest"),
    ]
    assert {path.name for path in report_paths} == {
        "gosec-report.json",
        "gitleaks-report.json",
        "trivy-report.json",
    }


def test_run_scanners_rejects_unimplemented_cpp_profile(tmp_path: Path) -> None:
    with pytest.raises(
        ScannerExecutionError,
        match="Language 'cpp' is detected but scanner profile is not implemented yet.",
    ):
        run_scanners(
            source=tmp_path,
            reports_dir=tmp_path / "reports",
            languages=[ProjectLanguage.CPP],
        )
