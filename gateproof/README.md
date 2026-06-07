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

## Real Security Gate Demo

The repository includes two demonstration applications:

- `examples/vulnerable-python-app`: intentionally contains demo security issues.
- `examples/clean-python-app`: minimal application without obvious source-level issues.

Install GateProof and Python scanners:

```bash
cd gateproof
pip install -e .[dev]
pip install bandit pip-audit
chmod +x scripts/run_security_tools.sh
```

The real scanner script also requires `gitleaks`, `trivy`, and Docker to be available on `PATH`.

Run scanners and GateProof for the vulnerable app:

```bash
./scripts/run_security_tools.sh examples/vulnerable-python-app

gateproof evaluate \
  --policy policies/default.yaml \
  --reports .gateproof/input \
  --output .gateproof/evidence \
  --commit demo-vulnerable
```

This scenario is expected to return `FAIL`.

Run scanners and GateProof for the clean app:

```bash
rm -rf .gateproof
./scripts/run_security_tools.sh examples/clean-python-app

gateproof evaluate \
  --policy policies/demo-pass.yaml \
  --reports .gateproof/input \
  --output .gateproof/evidence \
  --commit demo-clean
```

This scenario is expected to return `PASS` when the external scanner databases do not report high or critical issues for the current base image and dependencies. Trivy results can change over time as vulnerability databases are updated, so a clean-app container finding may require refreshing the base image for a stable PASS demo.

To run the real pipeline in GitHub Actions, open the `Security Gate Demo` workflow, choose `target` (`vulnerable` or `clean`), choose `policy` (`default` or `demo-pass`), and start the workflow manually. The workflow runs real scanners, evaluates GateProof, prints `gate-decision.json`, and uploads the evidence bundle as an artifact.

## Tests

```bash
pytest
```
