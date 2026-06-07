import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_trivy_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = [
        _to_finding(result, vulnerability, path)
        for result in payload.get("Results", [])
        for vulnerability in result.get("Vulnerabilities", []) or []
    ]

    return ScanReport(
        scan_type=ScanType.CONTAINER,
        source_tool="trivy",
        findings=findings,
        raw_report_path=str(path),
    )


def _to_finding(
    result: dict[str, Any],
    vulnerability: dict[str, Any],
    path: Path,
) -> Finding:
    target = str(result.get("Target", "unknown"))
    vulnerability_id = str(vulnerability.get("VulnerabilityID", "unknown"))
    package = str(vulnerability.get("PkgName", "unknown"))
    installed_version = str(vulnerability.get("InstalledVersion", "unknown"))

    return Finding(
        id=f"trivy:{vulnerability_id}:{package}:{installed_version}",
        source_tool="trivy",
        scan_type=ScanType.CONTAINER,
        rule_id=vulnerability_id,
        title=(
            vulnerability.get("Title")
            or f"Container vulnerability {vulnerability_id}"
        ),
        description=vulnerability.get("Description"),
        severity=_map_severity(vulnerability.get("Severity")),
        location=f"{target}:{package}@{installed_version}",
        cve=vulnerability_id if vulnerability_id.startswith("CVE-") else None,
        raw_reference=path.name,
    )


def _map_severity(value: Any) -> Severity:
    severity = str(value or "").upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(severity, Severity.UNKNOWN)

