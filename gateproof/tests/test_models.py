from gateproof.models import Finding, ScanReport, ScanType, Severity


def test_create_finding() -> None:
    finding = Finding(
        id="F-001",
        source_tool="mock",
        scan_type=ScanType.SAST,
        rule_id="RULE-1",
        title="Unsafe code pattern",
        description="Example security finding.",
        severity=Severity.HIGH,
        location="app.py:1",
        cve=None,
        raw_reference="mock://F-001",
    )

    assert finding.id == "F-001"
    assert finding.status == "OPEN"
    assert finding.blocking is False
    assert finding.severity == Severity.HIGH


def test_create_scan_report() -> None:
    finding = Finding(
        id="F-001",
        source_tool="mock",
        scan_type=ScanType.SAST,
        title="Unsafe code pattern",
        severity=Severity.LOW,
    )
    report = ScanReport(
        scan_type=ScanType.SAST,
        source_tool="mock",
        findings=[finding],
        raw_report_path="mock.json",
    )

    assert report.scan_type == ScanType.SAST
    assert report.source_tool == "mock"
    assert len(report.findings) == 1

