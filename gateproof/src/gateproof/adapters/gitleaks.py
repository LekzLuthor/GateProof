import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_gitleaks_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = [_to_finding(item, path) for item in payload]

    return ScanReport(
        scan_type=ScanType.SECRETS,
        source_tool="gitleaks",
        findings=findings,
        raw_report_path=str(path),
    )


def _to_finding(item: dict[str, Any], path: Path) -> Finding:
    rule_id = str(item.get("RuleID", "unknown"))
    file_path = str(item.get("File", "unknown"))
    start_line = item.get("StartLine")

    return Finding(
        id=f"gitleaks:{rule_id}:{file_path}:{start_line}",
        source_tool="gitleaks",
        scan_type=ScanType.SECRETS,
        rule_id=rule_id,
        title=f"Secret detected: {rule_id}",
        description=item.get("Description"),
        severity=Severity.HIGH,
        location=f"{file_path}:{start_line}",
        status="CONFIRMED",
        raw_reference=path.name,
    )

