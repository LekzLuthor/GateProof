from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class ScanType(StrEnum):
    SAST = "SAST"
    SCA = "SCA"
    SECRETS = "SECRETS"
    CONTAINER = "CONTAINER"
    FUZZING = "FUZZING"


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class Finding(BaseModel):
    id: str
    source_tool: str
    scan_type: ScanType
    rule_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity
    location: str | None = None
    cve: str | None = None
    status: str = "OPEN"
    raw_reference: str | None = None
    blocking: bool = False


class ScanReport(BaseModel):
    scan_type: ScanType
    source_tool: str
    findings: list[Finding]
    raw_report_path: str | None = None


class PolicyThreshold(BaseModel):
    critical: int | None = None
    high: int | None = None
    medium: int | None = None
    low: int | None = None
    info: int | None = None
    any_confirmed: int | None = None


class Policy(BaseModel):
    project_name: str
    profile: str
    required_scans: list[ScanType]
    required_tools: list[str] = Field(default_factory=list)
    thresholds: dict[ScanType, PolicyThreshold]
    sbom_required: bool = False
    evidence_bundle_required: bool = True
    fail_on_missing_required_scan: bool = True
    fail_on_missing_required_tool: bool = True
    fail_on_policy_violation: bool = True


class PolicyViolation(BaseModel):
    id: str
    message: str
    scan_type: ScanType | None = None
    severity: Severity | None = None
    actual_count: int | None = None
    allowed_count: int | None = None
    blocking: bool = True


class GateDecision(BaseModel):
    project_name: str
    commit_sha: str | None = None
    status: GateStatus
    policy_profile: str
    executed_scans: list[ScanType]
    executed_tools: list[str]
    findings_total: int
    findings_by_severity: dict[str, int]
    violations: list[PolicyViolation]
    explanation: str


class EvidenceManifest(BaseModel):
    project_name: str
    commit_sha: str | None = None
    generated_at: str
    gate_status: GateStatus
    artifacts: list[str]
    policy_snapshot: str | None = None
    normalized_findings: str | None = None
    decision_file: str | None = None
