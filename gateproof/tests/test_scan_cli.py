import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from gateproof.cli import app
from gateproof.scanners.runner import ProjectLanguage

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_cli_legacy_language_uses_runner_and_creates_failing_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    reports_dir = tmp_path / "reports"
    output_dir = tmp_path / "evidence"
    calls: list[dict[str, object]] = []

    def fake_run_scanners(
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
        calls.append(
            {
                "source": source,
                "reports_dir": reports_dir,
                "languages": languages,
                "image": image,
                "gitleaks_config": gitleaks_config,
                "include_container": include_container,
                "python_source": python_source,
                "python_requirements": python_requirements,
                "go_source": go_source,
                "go_packages": go_packages,
            }
        )
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_names = [
            "bandit-report.json",
            "pip-audit-report.json",
            "gitleaks-report.json",
            "trivy-report.json",
        ]
        for report_name in report_names:
            shutil.copyfile(
                FIXTURES_DIR / report_name,
                reports_dir / report_name,
            )
        return [reports_dir / report_name for report_name in report_names]

    monkeypatch.setattr("gateproof.cli.run_scanners", fake_run_scanners)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--policy",
            str(FIXTURES_DIR / "default_policy.yaml"),
            "--source",
            str(source),
            "--language",
            "python",
            "--reports",
            str(reports_dir),
            "--output",
            str(output_dir),
            "--commit",
            "abc123",
        ],
    )

    assert result.exit_code == 1
    assert "FAIL: Security gate failed" in result.output
    assert calls[0]["languages"] == [ProjectLanguage.PYTHON]
    assert calls[0]["source"] == source
    assert (output_dir / "gate-decision.json").exists()
    assert (output_dir / "findings-normalized.json").exists()
    assert (output_dir / "policy-snapshot.yaml").exists()
    assert (output_dir / "evidence-manifest.json").exists()
    assert (output_dir / "compliance-report.html").exists()

    manifest = json.loads(
        (output_dir / "evidence-manifest.json").read_text(encoding="utf-8")
    )
    assert "compliance-report.html" in manifest["artifacts"]


def test_scan_cli_languages_option_uses_runner(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    reports_dir = tmp_path / "reports"
    output_dir = tmp_path / "evidence"
    calls = _patch_fake_run_scanners(monkeypatch)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--policy",
            str(FIXTURES_DIR / "default_policy.yaml"),
            "--source",
            str(source),
            "--languages",
            "python",
            "--reports",
            str(reports_dir),
            "--output",
            str(output_dir),
        ],
    )

    assert result.exit_code == 1
    assert calls[0]["languages"] == [ProjectLanguage.PYTHON]


def test_scan_cli_cpp_language_returns_not_implemented(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--policy",
            str(FIXTURES_DIR / "default_policy.yaml"),
            "--source",
            str(source),
            "--languages",
            "cpp",
        ],
    )

    assert result.exit_code == 2
    assert "Language 'cpp' is detected but scanner profile is not implemented yet." in (
        result.output
    )


def test_scan_cli_uses_config(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    requirements = source / "requirements.txt"
    requirements.write_text("requests==2.19.1\n", encoding="utf-8")
    config_path = tmp_path / "gateproof.yaml"
    output_dir = tmp_path / "configured-evidence"
    reports_dir = tmp_path / "configured-reports"
    config_path.write_text(
        f"""
version: 1
scan:
  source: {source.as_posix()}
  languages:
    - python
  python:
    source: {source.as_posix()}
    requirements:
      - {requirements.as_posix()}
  container:
    enabled: false
evidence:
  reports: {reports_dir.as_posix()}
  output: {output_dir.as_posix()}
""",
        encoding="utf-8",
    )
    calls = _patch_fake_run_scanners(monkeypatch)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--config",
            str(config_path),
            "--policy",
            str(FIXTURES_DIR / "default_policy.yaml"),
        ],
    )

    assert result.exit_code == 1
    assert calls[0]["source"] == source
    assert calls[0]["languages"] == [ProjectLanguage.PYTHON]
    assert calls[0]["reports_dir"] == reports_dir
    assert calls[0]["include_container"] is False
    assert calls[0]["python_source"] == source
    assert calls[0]["python_requirements"] == [requirements]
    assert (output_dir / "gate-decision.json").exists()


def test_scan_cli_languages_override_config(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    config_path = tmp_path / "gateproof.yaml"
    config_path.write_text(
        f"""
version: 1
scan:
  source: {source.as_posix()}
  languages:
    - go
evidence:
  reports: {(tmp_path / "reports").as_posix()}
  output: {(tmp_path / "evidence").as_posix()}
""",
        encoding="utf-8",
    )
    calls = _patch_fake_run_scanners(monkeypatch)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--config",
            str(config_path),
            "--policy",
            str(FIXTURES_DIR / "default_policy.yaml"),
            "--languages",
            "python",
        ],
    )

    assert result.exit_code == 1
    assert calls[0]["languages"] == [ProjectLanguage.PYTHON]


def _patch_fake_run_scanners(monkeypatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def fake_run_scanners(
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
        calls.append(
            {
                "source": source,
                "reports_dir": reports_dir,
                "languages": languages,
                "image": image,
                "gitleaks_config": gitleaks_config,
                "include_container": include_container,
                "python_source": python_source,
                "python_requirements": python_requirements,
                "go_source": go_source,
                "go_packages": go_packages,
            }
        )
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_names = [
            "bandit-report.json",
            "pip-audit-report.json",
            "gitleaks-report.json",
            "trivy-report.json",
        ]
        for report_name in report_names:
            shutil.copyfile(
                FIXTURES_DIR / report_name,
                reports_dir / report_name,
            )
        return [reports_dir / report_name for report_name in report_names]

    monkeypatch.setattr("gateproof.cli.run_scanners", fake_run_scanners)
    return calls
