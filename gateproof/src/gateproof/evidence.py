import json
import shutil
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from gateproof.models import EvidenceManifest, GateDecision, ScanReport


def write_json(path: Path, data: BaseModel | dict[str, Any] | list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_to_jsonable(data), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_evidence_bundle(
    output_dir: Path,
    policy_path: Path,
    reports: list[ScanReport],
    decision: GateDecision,
) -> EvidenceManifest:
    output_dir.mkdir(parents=True, exist_ok=True)

    decision_file = output_dir / "gate-decision.json"
    normalized_findings = output_dir / "findings-normalized.json"
    policy_snapshot = output_dir / "policy-snapshot.yaml"
    manifest_file = output_dir / "evidence-manifest.json"

    write_json(decision_file, decision)
    write_json(
        normalized_findings,
        [finding for report in reports for finding in report.findings],
    )
    shutil.copyfile(policy_path, policy_snapshot)

    manifest = EvidenceManifest(
        project_name=decision.project_name,
        commit_sha=decision.commit_sha,
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        gate_status=decision.status,
        artifacts=[
            decision_file.name,
            normalized_findings.name,
            policy_snapshot.name,
            manifest_file.name,
        ],
        policy_snapshot=policy_snapshot.name,
        normalized_findings=normalized_findings.name,
        decision_file=decision_file.name,
    )
    write_json(manifest_file, manifest)

    return manifest


def _to_jsonable(data: BaseModel | dict[str, Any] | list[Any]) -> Any:
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json")
    if isinstance(data, Enum):
        return data.value
    if isinstance(data, list):
        return [_to_jsonable(item) for item in data]
    if isinstance(data, dict):
        return {key: _to_jsonable(value) for key, value in data.items()}
    return data
