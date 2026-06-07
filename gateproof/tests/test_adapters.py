from pathlib import Path

from gateproof.adapters.bandit import load_bandit_report
from gateproof.adapters.gitleaks import load_gitleaks_report
from gateproof.adapters.loader import load_reports_from_dir
from gateproof.adapters.pip_audit import load_pip_audit_report
from gateproof.adapters.trivy import load_trivy_report
from gateproof.models import ScanType, Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_bandit_adapter_maps_high_sast_finding() -> None:
    report = load_bandit_report(FIXTURES_DIR / "bandit-report.json")

    assert report.scan_type == ScanType.SAST
    assert report.source_tool == "bandit"
    assert report.findings[0].severity == Severity.HIGH


def test_pip_audit_adapter_maps_high_sca_finding() -> None:
    report = load_pip_audit_report(FIXTURES_DIR / "pip-audit-report.json")

    assert report.scan_type == ScanType.SCA
    assert report.source_tool == "pip-audit"
    assert report.findings[0].severity == Severity.HIGH
    assert report.findings[0].cve == "CVE-2019-19844"


def test_gitleaks_adapter_maps_confirmed_secret_without_secret_value() -> None:
    report = load_gitleaks_report(FIXTURES_DIR / "gitleaks-report.json")
    finding = report.findings[0]

    assert report.scan_type == ScanType.SECRETS
    assert finding.severity == Severity.HIGH
    assert finding.status == "CONFIRMED"
    assert "SUPER_SECRET_TOKEN" not in finding.title
    assert "SUPER_SECRET_TOKEN" not in (finding.description or "")


def test_trivy_adapter_maps_critical_container_finding() -> None:
    report = load_trivy_report(FIXTURES_DIR / "trivy-report.json")

    assert report.scan_type == ScanType.CONTAINER
    assert report.source_tool == "trivy"
    assert report.findings[0].severity in {Severity.CRITICAL, Severity.HIGH}
    assert report.findings[0].cve == "CVE-2024-12345"


def test_loader_loads_recognized_reports_from_fixtures_dir() -> None:
    reports = load_reports_from_dir(FIXTURES_DIR)
    source_tools = {report.source_tool for report in reports}

    assert {"bandit", "pip-audit", "gitleaks", "trivy"}.issubset(source_tools)
