"""CVSS risk scoring utility for Phantom reports."""

from tools import register_tool

SEVERITY_SCORES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.5,
    "low": 0.5,
    "info": 0.1,
}

TOOL_SPEC = {
    "name": "calculate_risk_score",
    "description": (
        "Calculate aggregate CVSS risk score from collected findings. "
        "Pass a list of findings, each with a 'severity' field "
        "(critical/high/medium/low/info). Returns score, label, and breakdown."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "description": "List of finding objects with 'severity' field",
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "name": {"type": "string"},
                    },
                },
            },
        },
        "required": ["findings"],
    },
}


@register_tool(TOOL_SPEC)
def run(findings: list = None, **kwargs) -> str:
    """Calculate aggregate risk score."""
    if not findings:
        return "No findings provided."

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        # Support both flat {"severity": "high"} and nested {"info": {"severity": "high"}}
        sev = f.get("severity") or (f.get("info", {}) or {}).get("severity") or "info"
        sev = sev.lower()
        if sev in breakdown:
            breakdown[sev] += 1

    total = sum(breakdown.values())
    if total == 0:
        return "No valid findings. Score: 0.0/10 (None)"

    weighted_sum = sum(
        breakdown[sev] * SEVERITY_WEIGHTS[sev] * SEVERITY_SCORES[sev]
        for sev in breakdown
    )
    weight_total = sum(breakdown[sev] * SEVERITY_WEIGHTS[sev] for sev in breakdown)
    score = round(min(10.0, weighted_sum / max(weight_total, 1.0)), 1)

    if score >= 9.0:
        label = "Critical"
    elif score >= 7.0:
        label = "High"
    elif score >= 4.0:
        label = "Medium"
    elif score >= 1.0:
        label = "Low"
    else:
        label = "Informational"

    lines = [
        f"Risk Score: {score}/10 ({label})",
        f"Total findings: {total}",
        f"  Critical: {breakdown['critical']}",
        f"  High: {breakdown['high']}",
        f"  Medium: {breakdown['medium']}",
        f"  Low: {breakdown['low']}",
        f"  Info: {breakdown['info']}",
    ]
    return "\n".join(lines)
