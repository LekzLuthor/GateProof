from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ProjectConfig(BaseModel):
    name: str | None = "unknown-project"


class PythonScanConfig(BaseModel):
    source: Path | None = None
    requirements: list[Path] = Field(default_factory=list)


class GoScanConfig(BaseModel):
    source: Path | None = None
    packages: list[str] = Field(default_factory=lambda: ["./..."])


class CommonScanConfig(BaseModel):
    gitleaks_config: Path | None = None


class ContainerScanConfig(BaseModel):
    enabled: bool = True
    image: str | None = None


class ScanConfig(BaseModel):
    source: Path = Path(".")
    languages: list[str] = Field(default_factory=lambda: ["auto"])
    python: PythonScanConfig = Field(default_factory=PythonScanConfig)
    go: GoScanConfig = Field(default_factory=GoScanConfig)
    common: CommonScanConfig = Field(default_factory=CommonScanConfig)
    container: ContainerScanConfig = Field(default_factory=ContainerScanConfig)


class EvidenceConfig(BaseModel):
    reports: Path = Path(".gateproof/input")
    output: Path = Path(".gateproof/evidence")


class GateProofConfig(BaseModel):
    version: int = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)


def load_config(path: Path) -> GateProofConfig:
    if not path.exists():
        raise ValueError(f"GateProof config file was not found: {path}")

    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config = GateProofConfig(**payload)

    if config.version != 1:
        raise ValueError(
            f"Unsupported GateProof config version {config.version}. "
            "Expected version 1."
        )

    return config

