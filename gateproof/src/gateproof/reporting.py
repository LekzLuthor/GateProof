from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from gateproof.models import EvidenceManifest, GateDecision


def render_text_summary(decision: GateDecision) -> str:
    return f"{decision.status.value}: {decision.explanation}"


def generate_html_report(
    output_dir: Path,
    decision: GateDecision,
    manifest: EvidenceManifest,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "compliance-report.html"

    if report_path.name not in manifest.artifacts:
        manifest.artifacts.append(report_path.name)

    template = _template_environment().get_template("compliance_report.html.j2")
    report_path.write_text(
        template.render(decision=decision, manifest=manifest),
        encoding="utf-8",
    )

    return report_path


def _template_environment() -> Environment:
    template_dir = _template_dir()
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def _template_dir() -> Path:
    package_template_dir = Path(__file__).resolve().parent / "templates"
    if (package_template_dir / "compliance_report.html.j2").exists():
        return package_template_dir

    cwd_template_dir = Path.cwd() / "templates"
    if (cwd_template_dir / "compliance_report.html.j2").exists():
        return cwd_template_dir

    return Path(__file__).resolve().parents[2] / "templates"
