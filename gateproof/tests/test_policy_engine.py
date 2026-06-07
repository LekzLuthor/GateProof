from pathlib import Path

from gateproof.models import Finding, GateStatus, ScanReport, ScanType, Severity
from gateproof.policy_engine import evaluate_policy, load_policy

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_policy_passes_when_required_scans_present_and_thresholds_satisfied() -> None:
    policy = load_policy(FIXTURES_DIR / "default_policy.yaml")
    reports = [_empty_report(scan_type) for scan_type in policy.required_scans]

    decision = evaluate_policy(policy, reports, commit_sha="abc123")

    assert decision.status == GateStatus.PASS
    assert decision.commit_sha == "abc123"
    assert decision.findings_total == 0
    assert decision.violations == []


def test_policy_fails_on_high_sast_finding() -> None:
    policy = load_policy(FIXTURES_DIR / "default_policy.yaml")
    reports = [_empty_report(scan_type) for scan_type in policy.required_scans]
    reports[0] = ScanReport(
        scan_type=ScanType.SAST,
        source_tool="mock",
        findings=[
            Finding(
                id="F-001",
                source_tool="mock",
                scan_type=ScanType.SAST,
                title="High severity SAST finding",
                severity=Severity.HIGH,
            )
        ],
    )

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.FAIL
    assert decision.findings_by_severity["HIGH"] == 1
    assert any(
        violation.id == "threshold_exceeded:SAST:HIGH"
        for violation in decision.violations
    )


def test_policy_fails_on_missing_required_scan() -> None:
    policy = load_policy(FIXTURES_DIR / "default_policy.yaml")
    reports = [_empty_report(ScanType.SAST)]

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.FAIL
    assert any(
        violation.id == "missing_required_scan:SCA"
        for violation in decision.violations
    )


def test_policy_required_tools_pass_when_tools_were_executed() -> None:
    policy = load_policy(FIXTURES_DIR / "default_policy.yaml").model_copy(
        update={"required_tools": ["mock"]}
    )
    reports = [_empty_report(scan_type) for scan_type in policy.required_scans]

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.PASS
    assert decision.executed_tools == ["mock"]
    assert decision.violations == []


def test_policy_fails_on_missing_required_tool() -> None:
    policy = load_policy(FIXTURES_DIR / "default_policy.yaml").model_copy(
        update={
            "required_tools": ["bandit"],
            "fail_on_missing_required_tool": True,
        }
    )
    reports = [_empty_report(scan_type) for scan_type in policy.required_scans]

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.FAIL
    assert any(
        violation.id == "missing_required_tool:bandit"
        for violation in decision.violations
    )


def test_python_go_policy_required_tools_pass_when_all_tools_present() -> None:
    policy = load_policy(Path("policies/python-go.yaml"))
    reports = [
        ScanReport(scan_type=ScanType.SAST, source_tool="bandit", findings=[]),
        ScanReport(scan_type=ScanType.SCA, source_tool="pip-audit", findings=[]),
        ScanReport(scan_type=ScanType.SAST, source_tool="gosec", findings=[]),
        ScanReport(scan_type=ScanType.SCA, source_tool="govulncheck", findings=[]),
        ScanReport(scan_type=ScanType.SECRETS, source_tool="gitleaks", findings=[]),
        ScanReport(scan_type=ScanType.CONTAINER, source_tool="trivy", findings=[]),
    ]

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.PASS
    assert decision.executed_tools == [
        "bandit",
        "pip-audit",
        "gosec",
        "govulncheck",
        "gitleaks",
        "trivy",
    ]


def test_python_go_policy_fails_when_govulncheck_is_missing() -> None:
    policy = load_policy(Path("policies/python-go.yaml"))
    reports = [
        ScanReport(scan_type=ScanType.SAST, source_tool="bandit", findings=[]),
        ScanReport(scan_type=ScanType.SCA, source_tool="pip-audit", findings=[]),
        ScanReport(scan_type=ScanType.SAST, source_tool="gosec", findings=[]),
        ScanReport(scan_type=ScanType.SECRETS, source_tool="gitleaks", findings=[]),
        ScanReport(scan_type=ScanType.CONTAINER, source_tool="trivy", findings=[]),
    ]

    decision = evaluate_policy(policy, reports)

    assert decision.status == GateStatus.FAIL
    assert any(
        violation.id == "missing_required_tool:govulncheck"
        for violation in decision.violations
    )


def _empty_report(scan_type: ScanType) -> ScanReport:
    return ScanReport(scan_type=scan_type, source_tool="mock", findings=[])
