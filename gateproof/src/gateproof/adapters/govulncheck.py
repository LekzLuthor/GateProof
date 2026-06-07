import json
from pathlib import Path
from typing import Any

from gateproof.models import Finding, ScanReport, ScanType, Severity


def load_govulncheck_report(path: Path) -> ScanReport:
    events = _parse_events(path.read_text(encoding="utf-8"))
    osv_summaries = _collect_osv_summaries(events)
    findings = [
        _to_finding(finding, osv_summaries, path)
        for event in events
        if (finding := _finding_from_event(event)) is not None
    ]

    return ScanReport(
        scan_type=ScanType.SCA,
        source_tool="govulncheck",
        findings=findings,
        raw_report_path=str(path),
    )


def _parse_events(text: str) -> list[dict[str, Any]]:
    if not text.strip():
        return []

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return _parse_concatenated_json(text)

    return _payload_to_events(payload)


def _parse_concatenated_json(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    index = 0
    length = len(text)

    while index < length:
        while index < length and text[index].isspace():
            index += 1

        if index >= length:
            break

        try:
            payload, next_index = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            line_events, next_index = _parse_json_line(text, index)
            events.extend(line_events)
            index = next_index
            continue

        events.extend(_payload_to_events(payload))
        index = next_index

    return events


def _parse_json_line(
    text: str,
    index: int,
) -> tuple[list[dict[str, Any]], int]:
    line_end = text.find("\n", index)
    if line_end == -1:
        line_end = len(text)

    line = text[index:line_end].strip()
    events: list[dict[str, Any]] = []
    if line:
        try:
            events = _payload_to_events(json.loads(line))
        except json.JSONDecodeError:
            pass

    return events, line_end + 1


def _payload_to_events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _collect_osv_summaries(events: list[dict[str, Any]]) -> dict[str, str]:
    summaries: dict[str, str] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        osv = event.get("osv")
        if not isinstance(osv, dict):
            continue
        osv_id = osv.get("id")
        summary = osv.get("summary")
        if osv_id and summary:
            summaries[str(osv_id)] = str(summary)
    return summaries


def _finding_from_event(event: Any) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None
    finding = event.get("finding")
    if isinstance(finding, dict):
        return finding
    if isinstance(event.get("osv"), str):
        return event
    return None


def _to_finding(
    finding: dict[str, Any],
    osv_summaries: dict[str, str],
    path: Path,
) -> Finding:
    osv_id = str(finding.get("osv") or "unknown")
    description = osv_summaries.get(osv_id, "Vulnerability reported by govulncheck")

    return Finding(
        id=f"govulncheck:{osv_id}:{_location_from_trace(finding, osv_id)}",
        source_tool="govulncheck",
        scan_type=ScanType.SCA,
        rule_id=osv_id,
        title=f"Go vulnerability {osv_id}",
        description=description,
        severity=Severity.HIGH,
        location=_location_from_trace(finding, osv_id),
        cve=osv_id if osv_id.startswith("CVE-") else None,
        raw_reference=path.name,
    )


def _location_from_trace(finding: dict[str, Any], fallback: str) -> str:
    trace = finding.get("trace")
    if not isinstance(trace, list) or not trace:
        return fallback

    first_item = trace[0]
    if not isinstance(first_item, dict):
        return fallback

    parts = [
        str(first_item[key])
        for key in ("module", "package", "function")
        if first_item.get(key)
    ]
    return ":".join(parts) if parts else fallback
