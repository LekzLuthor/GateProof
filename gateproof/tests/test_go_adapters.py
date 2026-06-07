from pathlib import Path

from gateproof.adapters.gosec import load_gosec_report
from gateproof.adapters.govulncheck import load_govulncheck_report
from gateproof.models import ScanType, Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_gosec_adapter_maps_high_sast_finding() -> None:
    report = load_gosec_report(FIXTURES_DIR / "gosec-report.json")
    finding = report.findings[0]

    assert report.scan_type == ScanType.SAST
    assert report.source_tool == "gosec"
    assert finding.severity == Severity.HIGH
    assert finding.rule_id == "G204"


def test_govulncheck_adapter_maps_json_lines_sca_finding() -> None:
    report = load_govulncheck_report(FIXTURES_DIR / "govulncheck-report.json")
    finding = report.findings[0]

    assert report.scan_type == ScanType.SCA
    assert report.source_tool == "govulncheck"
    assert finding.severity == Severity.HIGH
    assert finding.rule_id == "GO-2023-0001"
    assert finding.description == "demo vulnerable module"

