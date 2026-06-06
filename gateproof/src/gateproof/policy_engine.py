from collections import Counter
from pathlib import Path

import yaml

from gateproof.models import (
    Finding,
    GateDecision,
    GateStatus,
    Policy,
    PolicyThreshold,
    PolicyViolation,
    ScanReport,
    ScanType,
    Severity,
)


def load_policy(path: Path) -> Policy:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    project = payload.get("project", {})
    requirements = payload.get("requirements", {})
    decision = payload.get("decision", {})

    thresholds = {
        _parse_scan_type(scan_type): PolicyThreshold(**threshold)
        for scan_type, threshold in (payload.get("thresholds") or {}).items()
    }

    return Policy(
        project_name=project["name"],
        profile=project["profile"],
        required_scans=[
            _parse_scan_type(scan_type)
            for scan_type in payload.get("required_scans", [])
        ],
        thresholds=thresholds,
        sbom_required=requirements.get("sbom_required", False),
        evidence_bundle_required=requirements.get("evidence_bundle_required", True),
        fail_on_missing_required_scan=decision.get(
            "fail_on_missing_required_scan", True
        ),
        fail_on_policy_violation=decision.get("fail_on_policy_violation", True),
    )


def evaluate_policy(
    policy: Policy,
    reports: list[ScanReport],
    commit_sha: str | None = None,
) -> GateDecision:
    findings = [finding for report in reports for finding in report.findings]
    findings_by_severity = _count_findings_by_severity(findings)
    executed_scans = list(dict.fromkeys(report.scan_type for report in reports))

    violations: list[PolicyViolation] = []
    violations.extend(_check_required_scans(policy, executed_scans))
    violations.extend(_check_thresholds(policy, reports))

    blocking_violations = [violation for violation in violations if violation.blocking]
    status = GateStatus.FAIL if blocking_violations else GateStatus.PASS

    explanation = _build_explanation(
        status=status,
        blocking_violations_count=len(blocking_violations),
        violations_count=len(violations),
    )

    return GateDecision(
        project_name=policy.project_name,
        commit_sha=commit_sha,
        status=status,
        policy_profile=policy.profile,
        executed_scans=executed_scans,
        findings_total=len(findings),
        findings_by_severity=findings_by_severity,
        violations=violations,
        explanation=explanation,
    )


def _parse_scan_type(value: str | ScanType) -> ScanType:
    if isinstance(value, ScanType):
        return value
    return ScanType(value.upper())


def _count_findings_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity.value: counts.get(severity, 0) for severity in Severity}


def _check_required_scans(
    policy: Policy,
    executed_scans: list[ScanType],
) -> list[PolicyViolation]:
    executed = set(executed_scans)
    violations: list[PolicyViolation] = []

    for required_scan in policy.required_scans:
        if required_scan not in executed:
            violations.append(
                PolicyViolation(
                    id=f"missing_required_scan:{required_scan.value}",
                    message=f"Required scan {required_scan.value} was not executed.",
                    scan_type=required_scan,
                    severity=None,
                    actual_count=0,
                    allowed_count=0,
                    blocking=policy.fail_on_missing_required_scan,
                )
            )

    return violations


def _check_thresholds(policy: Policy, reports: list[ScanReport]) -> list[PolicyViolation]:
    findings_by_scan_type: dict[ScanType, list[Finding]] = {}
    for report in reports:
        findings_by_scan_type.setdefault(report.scan_type, []).extend(report.findings)

    violations: list[PolicyViolation] = []
    for scan_type, threshold in policy.thresholds.items():
        scan_findings = findings_by_scan_type.get(scan_type, [])
        severity_counts = Counter(finding.severity for finding in scan_findings)

        for severity, field_name in (
            (Severity.CRITICAL, "critical"),
            (Severity.HIGH, "high"),
            (Severity.MEDIUM, "medium"),
            (Severity.LOW, "low"),
            (Severity.INFO, "info"),
        ):
            allowed_count = getattr(threshold, field_name)
            if allowed_count is None:
                continue

            actual_count = severity_counts.get(severity, 0)
            if actual_count > allowed_count:
                violations.append(
                    PolicyViolation(
                        id=(
                            f"threshold_exceeded:{scan_type.value}:"
                            f"{severity.value}"
                        ),
                        message=(
                            f"{scan_type.value} has {actual_count} "
                            f"{severity.value} findings, allowed {allowed_count}."
                        ),
                        scan_type=scan_type,
                        severity=severity,
                        actual_count=actual_count,
                        allowed_count=allowed_count,
                        blocking=policy.fail_on_policy_violation,
                    )
                )

        if threshold.any_confirmed is not None:
            confirmed_count = sum(
                1
                for finding in scan_findings
                if finding.status.upper() == "CONFIRMED"
            )
            if confirmed_count > threshold.any_confirmed:
                violations.append(
                    PolicyViolation(
                        id=f"threshold_exceeded:{scan_type.value}:CONFIRMED",
                        message=(
                            f"{scan_type.value} has {confirmed_count} confirmed "
                            f"findings, allowed {threshold.any_confirmed}."
                        ),
                        scan_type=scan_type,
                        severity=None,
                        actual_count=confirmed_count,
                        allowed_count=threshold.any_confirmed,
                        blocking=policy.fail_on_policy_violation,
                    )
                )

    return violations


def _build_explanation(
    status: GateStatus,
    blocking_violations_count: int,
    violations_count: int,
) -> str:
    if status == GateStatus.PASS:
        if violations_count:
            return (
                "Security gate passed: policy checks completed with "
                f"{violations_count} non-blocking violation(s)."
            )
        return (
            "Security gate passed: all required scans are present and policy "
            "thresholds are satisfied."
        )

    return (
        "Security gate failed: "
        f"{blocking_violations_count} blocking policy violation(s) detected."
    )

