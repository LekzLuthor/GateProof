import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_pip_audit_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies = (
        payload
        if isinstance(payload, list)
        else payload.get("dependencies", [])
    )

    findings = [
        _to_finding(dependency, vulnerability, path)
        for dependency in dependencies
        for vulnerability in dependency.get("vulns", [])
    ]

    return ScanReport(
        scan_type=ScanType.SCA,
        source_tool="pip-audit",
        findings=findings,
        raw_report_path=str(path),
    )


def _to_finding(
    dependency: dict[str, Any],
    vulnerability: dict[str, Any],
    path: Path,
) -> Finding:
    package = str(dependency.get("name", "unknown"))
    version = str(dependency.get("version", "unknown"))
    vuln_id = str(vulnerability.get("id", "unknown"))

    return Finding(
        id=f"pip-audit:{package}:{vuln_id}",
        source_tool="pip-audit",
        scan_type=ScanType.SCA,
        rule_id=vuln_id,
        title=f"Vulnerable dependency {package} {version}",
        description=vulnerability.get("description"),
        severity=Severity.HIGH,
        location=f"{package}=={version}",
        cve=_first_cve(vulnerability.get("aliases") or []),
        raw_reference=path.name,
    )


def _first_cve(aliases: list[Any]) -> str | None:
    for alias in aliases:
        alias_value = str(alias)
        if alias_value.startswith("CVE-"):
            return alias_value
    return None
