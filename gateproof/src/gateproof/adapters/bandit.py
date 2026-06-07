import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_bandit_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = [_to_finding(result, path) for result in payload.get("results", [])]

    return ScanReport(
        scan_type=ScanType.SAST,
        source_tool="bandit",
        findings=findings,
        raw_report_path=str(path),
    )


def _to_finding(result: dict[str, Any], path: Path) -> Finding:
    filename = str(result.get("filename", "unknown"))
    line_number = result.get("line_number")
    test_id = str(result.get("test_id", "unknown"))

    return Finding(
        id=f"bandit:{test_id}:{filename}:{line_number}",
        source_tool="bandit",
        scan_type=ScanType.SAST,
        rule_id=test_id,
        title=str(result.get("test_name") or test_id),
        description=result.get("issue_text"),
        severity=_map_severity(result.get("issue_severity")),
        location=f"{filename}:{line_number}",
        raw_reference=path.name,
    )


def _map_severity(value: Any) -> Severity:
    severity = str(value or "").upper()
    return {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(severity, Severity.UNKNOWN)

