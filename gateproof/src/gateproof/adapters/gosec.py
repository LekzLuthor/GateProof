import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_gosec_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = [_to_finding(issue, path) for issue in payload.get("Issues", []) or []]

    return ScanReport(
        scan_type=ScanType.SAST,
        source_tool="gosec",
        findings=findings,
        raw_report_path=str(path),
    )


def _to_finding(issue: dict[str, Any], path: Path) -> Finding:
    rule_id = issue.get("rule_id") or issue.get("rule")
    file_path = str(issue.get("file", "unknown"))
    line = issue.get("line", "unknown")
    title = issue.get("details") or f"Go security finding {rule_id or 'unknown'}"

    return Finding(
        id=f"gosec:{rule_id}:{file_path}:{line}",
        source_tool="gosec",
        scan_type=ScanType.SAST,
        rule_id=rule_id,
        title=str(title),
        description=issue.get("details"),
        severity=_map_severity(issue.get("severity")),
        location=f"{file_path}:{line}",
        raw_reference=path.name,
    )


def _map_severity(value: Any) -> Severity:
    severity = str(value or "").upper()
    return {
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(severity, Severity.UNKNOWN)

