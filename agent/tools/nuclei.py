"""Fast CVE and misconfiguration scanner (Nuclei)."""

import os
import json
import logging
import subprocess
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)


def run(target: str, templates: str = "http/cves", severity: str = "critical,high") -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("nuclei.json")
    cmd = [
        "nuclei", "-u", target, "-t", templates,
        "-severity", severity, "-json", "-silent", "-o", output_path,
    ]

    logger.info("Running nuclei: %s (templates=%s, severity=%s)", target, templates, severity)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        source = result.stdout.strip()
        if not source and os.path.exists(output_path):
            with open(output_path, encoding="utf-8", errors="replace") as f:
                source = f.read()

        findings = []
        for line in source.splitlines():
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if not findings:
            return "Nuclei done \u2013 0 findings"

        summary = f"Nuclei done \u2013 {len(findings)} findings:\n"
        for finding in findings[:15]:
            cve_list = (finding.get("info", {}).get("classification") or {}).get("cve-id") or []
            cve = cve_list[0] if cve_list else finding.get("template-id", "")
            name = finding.get("info", {}).get("name", "unknown")
            sev = finding.get("info", {}).get("severity", "?").upper()
            matched = finding.get("matched-at", finding.get("host", ""))
            summary += f"  [{sev}] {cve or name} \u2192 {matched}\n"

        if len(findings) > 15:
            summary += f"  ... +{len(findings) - 15} more (use read_log 'nuclei.json')"

        logger.info("Nuclei found %d findings on %s", len(findings), target)
        return summary.strip()

    except FileNotFoundError:
        return "[TOOL OK, BINARY MISSING] nuclei is not installed on this system. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest or download from github.com/projectdiscovery/nuclei/releases. This does NOT mean the run_nuclei tool is unavailable — it just needs the nuclei binary."
    except Exception as e:
        logger.error("Nuclei error: %s", e)
        return f"Nuclei error: {str(e)}"


TOOL_SPEC = {
    "name": "run_nuclei",
    "description": "Fast CVE and misconfiguration scanner (Nuclei)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "string", "default": "http/cves"},
            "severity": {"type": "string", "default": "critical,high", "description": "Comma-separated severities (e.g. critical,high,medium)"},
        },
        "required": ["target"],
    },
}
