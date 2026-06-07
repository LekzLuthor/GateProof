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

## One-command Scan Mode

GateProof has two operating modes:

- `gateproof evaluate` accepts already prepared JSON security reports.
- `gateproof scan` runs scanners first, writes reports to `.gateproof/input`, and then performs the same evaluation and evidence generation flow.

Example for a Python/FastAPI project:

```bash
pip install "git+https://github.com/LekzLuthor/GateProof.git#subdirectory=gateproof"

gateproof scan \
  --policy policies/security-gate.yaml \
  --source . \
  --language python \
  --image my-fastapi-app:${GITHUB_SHA} \
  --output .gateproof/evidence \
  --commit "${GITHUB_SHA}"
```

Minimal GitHub Actions usage:

```yaml
- name: Install GateProof
  run: |
    python -m pip install --upgrade pip
    pip install "git+https://github.com/LekzLuthor/GateProof.git#subdirectory=gateproof"
    pip install bandit pip-audit
    # install gitleaks and trivy

- name: Run GateProof scan
  run: |
    gateproof scan \
      --policy policies/security-gate.yaml \
      --source . \
      --language python \
      --image my-app:${{ github.sha }} \
      --output .gateproof/evidence \
      --commit "${{ github.sha }}"
```

## GitHub Action Usage

GateProof can be used in GitHub Actions in two ways.

### Variant A. CLI Scan Mode

Install the package yourself, install the external scanners, and call `gateproof scan`:

```yaml
- name: Install GateProof
  run: |
    python -m pip install --upgrade pip
    pip install "git+https://github.com/LekzLuthor/GateProof.git#subdirectory=gateproof"

- name: Run GateProof scan
  run: |
    gateproof scan \
      --policy policies/security-gate.yaml \
      --source . \
      --language python \
      --image my-app:${{ github.sha }} \
      --output .gateproof/evidence \
      --commit "${{ github.sha }}"
```

### Variant B. Composite Action

Use the GateProof composite action as a single `uses` step:

```yaml
- name: Run GateProof
  uses: LekzLuthor/GateProof/.github/actions/gateproof@main
  with:
    policy: policies/security-gate.yaml
    source: .
    language: python
    image: my-app:${{ github.sha }}
    output: .gateproof/evidence
```

The composite action installs GateProof, Bandit, pip-audit, Gitleaks, and Trivy, then runs `gateproof scan`. Upload the generated evidence bundle with a separate `actions/upload-artifact` step. For demonstration FAIL scenarios, use `continue-on-error: true` on the GateProof step when you still want later artifact upload steps to run.

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

`policies/default.yaml` is the strict release-control policy for the vulnerable demo. It blocks high and critical findings across the required scan types.

`policies/demo-pass.yaml` is a demonstration baseline-tolerant policy for a reproducible clean-app PASS scenario. It still blocks high and critical SAST and SCA findings, and blocks high severity secrets, but it allows container CVEs from the current base image within the demo baseline. For production, use a strict policy and/or an explicit waiver or exception mechanism with justification and an expiration date.

`.gitleaks.toml` contains a custom rule only for the intentionally vulnerable GateProof demo secret. It exists to make the experiment reproducible and should not be treated as a full production secret-detection policy.

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

This scenario is expected to return `PASS`. Container findings can still be present, but the `demo-pass` policy tolerates them as part of the demo baseline. Trivy results can change over time as vulnerability databases are updated, so production use should prefer strict thresholds plus explicit exceptions.

To run the real pipeline in GitHub Actions, open the `Security Gate Demo` workflow, choose `target` (`vulnerable` or `clean`), choose `policy` (`default` or `demo-pass`), and start the workflow manually. The workflow runs real scanners, evaluates GateProof, prints `gate-decision.json`, and uploads the evidence bundle as an artifact.

## Tests

```bash
pytest
```
