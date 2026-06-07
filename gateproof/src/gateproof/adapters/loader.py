from collections.abc import Callable
from pathlib import Path

from gateproof.adapters.bandit import load_bandit_report
from gateproof.adapters.gitleaks import load_gitleaks_report
from gateproof.adapters.gosec import load_gosec_report
from gateproof.adapters.govulncheck import load_govulncheck_report
from gateproof.adapters.mock import load_mock_report
from gateproof.adapters.pip_audit import load_pip_audit_report
from gateproof.adapters.trivy import load_trivy_report
from gateproof.models import ScanReport

ReportLoader = Callable[[Path], ScanReport]


def load_reports_from_dir(reports_dir: Path) -> list[ScanReport]:
    reports: list[ScanReport] = []

    for report_path in sorted(reports_dir.glob("*.json")):
        loader = _select_loader(report_path.name)
        if loader is None:
            continue
        reports.append(loader(report_path))

    if not reports:
        raise ValueError(
            f"No recognized JSON security reports were found in {reports_dir}."
        )

    return reports


def _select_loader(filename: str) -> ReportLoader | None:
    normalized = filename.lower()

    if "mock" in normalized:
        return load_mock_report
    if "govulncheck" in normalized or "go-vuln" in normalized:
        return load_govulncheck_report
    if "gosec" in normalized:
        return load_gosec_report
    if "bandit" in normalized or "sast" in normalized:
        return load_bandit_report
    if (
        "pip-audit" in normalized
        or "pipaudit" in normalized
        or "sca" in normalized
    ):
        return load_pip_audit_report
    if "gitleaks" in normalized or "secrets" in normalized:
        return load_gitleaks_report
    if "trivy" in normalized or "container" in normalized:
        return load_trivy_report

    return None
