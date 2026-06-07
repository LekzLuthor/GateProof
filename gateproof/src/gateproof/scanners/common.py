import shutil
import subprocess
from pathlib import Path


class ScannerExecutionError(RuntimeError):
    pass


def ensure_tool_available(tool: str) -> None:
    if shutil.which(tool) is None:
        raise ScannerExecutionError(
            f"Required scanner is not available on PATH: {tool}"
        )


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    allow_failure: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.returncode != 0 and not allow_failure:
        command_name = command[0] if command else "<unknown>"
        raise ScannerExecutionError(
            f"Command failed with exit code {completed.returncode}: "
            f"{command_name}"
        )

    return completed


def ensure_json_file(path: Path, default_content: str) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(default_content, encoding="utf-8")

