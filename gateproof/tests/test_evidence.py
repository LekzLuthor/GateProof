import json
from pathlib import Path

from gateproof.evidence import build_evidence_bundle
from gateproof.models import GateStatus, ScanReport, ScanType
from gateproof.policy_engine import evaluate_policy, load_policy


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_build_evidence_bundle_creates_expected_files(tmp_path: Path) -> None:
    policy_path = FIXTURES_DIR / "default_policy.yaml"
    policy = load_policy(policy_path)
    reports = [
        ScanReport(scan_type=scan_type, source_tool="mock", findings=[])
        for scan_type in policy.required_scans
    ]
    decision = evaluate_policy(policy, reports, commit_sha="abc123")

    manifest = build_evidence_bundle(tmp_path, policy_path, reports, decision)

    assert manifest.gate_status == GateStatus.PASS
    assert (tmp_path / "gate-decision.json").exists()
    assert (tmp_path / "findings-normalized.json").exists()
    assert (tmp_path / "evidence-manifest.json").exists()
    assert (tmp_path / "policy-snapshot.yaml").exists()

    decision_payload = json.loads((tmp_path / "gate-decision.json").read_text())
    manifest_payload = json.loads((tmp_path / "evidence-manifest.json").read_text())

    assert decision_payload["status"] == "PASS"
    assert manifest_payload["decision_file"] == "gate-decision.json"
    assert manifest_payload["normalized_findings"] == "findings-normalized.json"
