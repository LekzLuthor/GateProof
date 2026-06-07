#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-}"
INPUT_DIR=".gateproof/input"
GITLEAKS_CONFIG=".gitleaks.toml"

if [[ -z "$APP_DIR" ]]; then
  echo "Usage: $0 <app-dir>" >&2
  exit 2
fi

if [[ ! -d "$APP_DIR" ]]; then
  echo "Application directory does not exist: $APP_DIR" >&2
  exit 2
fi

if [[ ! -f "$APP_DIR/requirements.txt" ]]; then
  echo "requirements.txt does not exist in: $APP_DIR" >&2
  exit 2
fi

for tool in bandit pip-audit gitleaks docker trivy; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "Required tool is not installed or not on PATH: $tool" >&2
    exit 127
  fi
done

mkdir -p "$INPUT_DIR"

bandit -r "$APP_DIR" -f json -o "$INPUT_DIR/bandit-report.json" || true
test -f "$INPUT_DIR/bandit-report.json" || echo '{"results":[]}' > "$INPUT_DIR/bandit-report.json"

pip-audit -r "$APP_DIR/requirements.txt" -f json -o "$INPUT_DIR/pip-audit-report.json" || true
test -f "$INPUT_DIR/pip-audit-report.json" || echo '{"dependencies":[]}' > "$INPUT_DIR/pip-audit-report.json"

if [[ -f "$GITLEAKS_CONFIG" ]]; then
  gitleaks detect \
    --source "$APP_DIR" \
    --config "$GITLEAKS_CONFIG" \
    --report-format json \
    --report-path "$INPUT_DIR/gitleaks-report.json" \
    --no-git \
    || true
else
  gitleaks detect \
    --source "$APP_DIR" \
    --report-format json \
    --report-path "$INPUT_DIR/gitleaks-report.json" \
    --no-git \
    || true
fi
test -f "$INPUT_DIR/gitleaks-report.json" || echo "[]" > "$INPUT_DIR/gitleaks-report.json"

IMAGE_NAME="gateproof-demo:local"
docker build -t "$IMAGE_NAME" "$APP_DIR"
trivy image --format json --output "$INPUT_DIR/trivy-report.json" "$IMAGE_NAME" || true
test -f "$INPUT_DIR/trivy-report.json" || echo '{"Results":[]}' > "$INPUT_DIR/trivy-report.json"

echo "Security reports written to $INPUT_DIR"
