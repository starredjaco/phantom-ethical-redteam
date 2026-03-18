"""CVSS risk scoring utility for Phantom reports."""

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


def calculate_risk_score(findings: list[dict]) -> dict:
    """
    Calculate aggregate risk score from nuclei-style findings.

    Each finding should have info.severity (critical/high/medium/low/info).
    Returns: {score, label, breakdown, total_findings}
    """
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = (f.get("info", {}).get("severity") or "info").lower()
        if sev in breakdown:
            breakdown[sev] += 1

    total = sum(breakdown.values())
    if total == 0:
        return {"score": 0.0, "label": "None", "breakdown": breakdown, "total_findings": 0}

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

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        "total_findings": total,
    }
