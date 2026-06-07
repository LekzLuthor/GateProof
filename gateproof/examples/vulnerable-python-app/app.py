"""Intentionally vulnerable demo application for GateProof."""

import subprocess

# Intentionally vulnerable demo data. This is a public test value, not a real key.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def run_healthcheck(host: str) -> str:
    command = f"ping -c 1 {host}"
    return subprocess.check_output(command, shell=True, text=True)


def main() -> None:
    print("GateProof vulnerable demo app")
    print(f"Configured demo key prefix: {AWS_ACCESS_KEY_ID[:4]}")


if __name__ == "__main__":
    main()

