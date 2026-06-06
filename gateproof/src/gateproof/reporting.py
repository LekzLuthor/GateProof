from gateproof.models import GateDecision


def render_text_summary(decision: GateDecision) -> str:
    return f"{decision.status.value}: {decision.explanation}"

