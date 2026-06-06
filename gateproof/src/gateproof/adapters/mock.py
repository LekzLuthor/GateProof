import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType


def load_mock_report(path: Path) -> ScanReport:
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        report_data: dict[str, Any] = {
            "scan_type": "SAST",
            "source_tool": "mock",
            "findings": payload,
        }
    else:
        report_data = payload

    scan_type = ScanType(str(report_data.get("scan_type", "SAST")).upper())
    source_tool = str(report_data.get("source_tool", "mock"))
    findings = [
        Finding(
            source_tool=item.get("source_tool", source_tool),
            scan_type=item.get("scan_type", scan_type),
            **{
                key: value
                for key, value in item.items()
                if key not in {"source_tool", "scan_type"}
            },
        )
        for item in report_data.get("findings", [])
    ]

    return ScanReport(
        scan_type=scan_type,
        source_tool=source_tool,
        findings=findings,
        raw_report_path=str(path),
    )

