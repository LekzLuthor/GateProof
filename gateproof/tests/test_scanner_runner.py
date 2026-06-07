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


def test_run_scanners_rejects_unimplemented_go_profile(tmp_path: Path) -> None:
    with pytest.raises(
        ScannerExecutionError,
        match="Language 'go' is detected but scanner profile is not implemented yet.",
    ):
        run_scanners(
            source=tmp_path,
            reports_dir=tmp_path / "reports",
            languages=[ProjectLanguage.GO],
        )
