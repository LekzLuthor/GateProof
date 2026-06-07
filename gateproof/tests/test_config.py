from pathlib import Path

import pytest

from gateproof.config import load_config


def test_load_empty_config_uses_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "gateproof.yaml"
    config_path.write_text("", encoding="utf-8")

    config = load_config(config_path)

    assert config.version == 1
    assert config.project.name == "unknown-project"
    assert config.scan.source == Path(".")
    assert config.scan.languages == ["auto"]
    assert config.scan.python.source is None
    assert config.scan.python.requirements == []
    assert config.scan.go.source is None
    assert config.scan.go.packages == ["./..."]
    assert config.scan.common.gitleaks_config is None
    assert config.scan.container.enabled is True
    assert config.scan.container.image is None
    assert config.evidence.reports == Path(".gateproof/input")
    assert config.evidence.output == Path(".gateproof/evidence")


def test_load_full_config(tmp_path: Path) -> None:
    config_path = tmp_path / "gateproof.yaml"
    config_path.write_text(
        """
version: 1
project:
  name: example-service
scan:
  source: service
  languages:
    - python
  python:
    source: service/python
    requirements:
      - service/requirements.txt
  go:
    source: service/go
    packages:
      - ./...
  common:
    gitleaks_config: service/.gitleaks.toml
  container:
    enabled: false
    image: example:latest
evidence:
  reports: build/input
  output: build/evidence
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.project.name == "example-service"
    assert config.scan.source == Path("service")
    assert config.scan.languages == ["python"]
    assert config.scan.python.source == Path("service/python")
    assert config.scan.python.requirements == [Path("service/requirements.txt")]
    assert config.scan.go.source == Path("service/go")
    assert config.scan.common.gitleaks_config == Path("service/.gitleaks.toml")
    assert config.scan.container.enabled is False
    assert config.scan.container.image == "example:latest"
    assert config.evidence.reports == Path("build/input")
    assert config.evidence.output == Path("build/evidence")


def test_load_config_rejects_invalid_version(tmp_path: Path) -> None:
    config_path = tmp_path / "gateproof.yaml"
    config_path.write_text("version: 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported GateProof config version 2"):
        load_config(config_path)


def test_load_config_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="GateProof config file was not found"):
        load_config(tmp_path / "missing.yaml")

