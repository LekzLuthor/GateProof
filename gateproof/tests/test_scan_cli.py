import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from gateproof.cli import app
from gateproof.scanners.runner import ProjectLanguage

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_cli_uses_runner_and_creates_failing_evidence(
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
        language: ProjectLanguage,
        image: str | None = None,
        gitleaks_config: Path | None = None,
        include_container: bool = True,
    ) -> list[Path]:
        calls.append(
            {
                "source": source,
                "reports_dir": reports_dir,
                "language": language,
                "image": image,
                "gitleaks_config": gitleaks_config,
                "include_container": include_container,
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
    assert calls[0]["language"] == ProjectLanguage.PYTHON
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
