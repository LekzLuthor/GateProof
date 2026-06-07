# GateProof

GateProof is a research prototype for a CI/CD security gate. It ingests normalized security scan results, applies Policy-as-Code rules, and produces a PASS or FAIL decision with an evidence bundle.

## Purpose

The prototype is intended for a bachelor thesis experiment. At this stage it provides the project skeleton, data models, a CLI, a policy engine, evidence bundle generation, a mock adapter, and report adapters for Bandit, pip-audit, Gitleaks, and Trivy JSON outputs.

## Example Run

```bash
gateproof evaluate \
  --policy policies/default.yaml \
  --mock-report tests/fixtures/mock_findings.json \
  --output .gateproof/evidence \
  --commit demo-commit
```

The bundled mock report violates the default policy, so this example is expected to exit with code `1`.

GateProof can also load a directory of JSON reports and select adapters by file name:

```bash
gateproof evaluate \
  --policy policies/default.yaml \
  --reports tests/fixtures \
  --output .gateproof/evidence \
  --commit demo-commit
```

If the directory contains high or critical findings, the security gate is expected to finish with `FAIL`.

## Example Policy

```yaml
project:
  name: vulnerable-python-app
  profile: secure-release

required_scans:
  - SAST
  - SCA
  - SECRETS
  - CONTAINER

requirements:
  sbom_required: true
  evidence_bundle_required: true

thresholds:
  SAST:
    critical: 0
    high: 0
  SCA:
    critical: 0
    high: 0
  SECRETS:
    high: 0
  CONTAINER:
    critical: 0
    high: 0

decision:
  fail_on_missing_required_scan: true
  fail_on_policy_violation: true
```

## Evidence Artifacts

GateProof writes the following artifacts to the output directory:

- `gate-decision.json`: final PASS or FAIL decision.
- `findings-normalized.json`: normalized findings consumed by the policy engine.
- `policy-snapshot.yaml`: copy of the policy used for the decision.
- `evidence-manifest.json`: manifest describing the generated bundle.
- `compliance-report.html`: HTML report with the decision, violations, and artifact list.

## Tests

```bash
pytest
```
