"""Compare two mission sessions to identify new/resolved/persistent findings."""

import json
import os
import logging

logger = logging.getLogger(__name__)


def _load_nuclei_findings(session_dir: str) -> list[dict]:
    """Load nuclei findings from a session directory."""
    findings = []
    for fname in os.listdir(session_dir):
        if "nuclei" in fname and fname.endswith(".json"):
            path = os.path.join(session_dir, fname)
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    return findings


def _load_ffuf_results(session_dir: str) -> list[dict]:
    """Load ffuf results from a session directory."""
    results = []
    for fname in os.listdir(session_dir):
        if "ffuf" in fname and fname.endswith(".json"):
            path = os.path.join(session_dir, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                results.extend(data.get("results", []))
            except (json.JSONDecodeError, Exception):
                pass
    return results


def _finding_key(f: dict) -> str:
    """Create a unique key for a nuclei finding."""
    cve_list = (f.get("info", {}).get("classification") or {}).get("cve-id") or []
    cve = cve_list[0] if cve_list else f.get("template-id", "unknown")
    matched = f.get("matched-at", f.get("host", ""))
    return f"{cve}|{matched}"


def _endpoint_key(r: dict) -> str:
    """Create a unique key for an ffuf result."""
    url = r.get("url", "")
    status = r.get("status", "?")
    return f"{status}|{url}"


def run(session_a: str, session_b: str) -> str:
    logs_dir = "logs"
    dir_a = os.path.join(logs_dir, session_a)
    dir_b = os.path.join(logs_dir, session_b)

    if not os.path.isdir(dir_a):
        return f"Session not found: {session_a}"
    if not os.path.isdir(dir_b):
        return f"Session not found: {session_b}"

    # Compare nuclei findings
    findings_a = _load_nuclei_findings(dir_a)
    findings_b = _load_nuclei_findings(dir_b)

    keys_a = {_finding_key(f): f for f in findings_a}
    keys_b = {_finding_key(f): f for f in findings_b}

    new_findings = [keys_b[k] for k in keys_b if k not in keys_a]
    resolved = [keys_a[k] for k in keys_a if k not in keys_b]
    persistent = [keys_b[k] for k in keys_b if k in keys_a]

    # Compare ffuf results
    ffuf_a = _load_ffuf_results(dir_a)
    ffuf_b = _load_ffuf_results(dir_b)

    ep_keys_a = {_endpoint_key(r) for r in ffuf_a}
    ep_keys_b = {_endpoint_key(r) for r in ffuf_b}
    new_endpoints = ep_keys_b - ep_keys_a
    removed_endpoints = ep_keys_a - ep_keys_b

    # Severity distribution
    def sev_dist(findings):
        dist = {}
        for f in findings:
            sev = (f.get("info", {}).get("severity") or "info").lower()
            dist[sev] = dist.get(sev, 0) + 1
        return dist

    dist_a = sev_dist(findings_a)
    dist_b = sev_dist(findings_b)

    # Build report
    report = f"Mission Diff: {session_a} -> {session_b}\n{'=' * 50}\n\n"

    report += f"## Vulnerability Findings\n"
    report += f"  Session A: {len(findings_a)} findings | Session B: {len(findings_b)} findings\n\n"

    if new_findings:
        report += f"  NEW ({len(new_findings)}):\n"
        for f in new_findings[:15]:
            sev = (f.get("info", {}).get("severity") or "?").upper()
            name = f.get("info", {}).get("name", "?")
            report += f"    [+] [{sev}] {name}\n"
    else:
        report += "  NEW: None\n"

    if resolved:
        report += f"\n  RESOLVED ({len(resolved)}):\n"
        for f in resolved[:15]:
            sev = (f.get("info", {}).get("severity") or "?").upper()
            name = f.get("info", {}).get("name", "?")
            report += f"    [-] [{sev}] {name}\n"
    else:
        report += "\n  RESOLVED: None\n"

    report += f"\n  PERSISTENT: {len(persistent)} findings\n"

    report += f"\n## Severity Distribution\n"
    report += f"  Session A: {dist_a}\n"
    report += f"  Session B: {dist_b}\n"

    report += f"\n## Endpoints\n"
    report += f"  New endpoints: {len(new_endpoints)}\n"
    report += f"  Removed endpoints: {len(removed_endpoints)}\n"

    for ep in sorted(new_endpoints)[:10]:
        report += f"    [+] {ep}\n"
    for ep in sorted(removed_endpoints)[:10]:
        report += f"    [-] {ep}\n"

    logger.info("Mission diff: %s vs %s", session_a, session_b)
    return report.strip()


TOOL_SPEC = {
    "name": "compare_missions",
    "description": (
        "Compare two mission sessions to identify new, resolved, and persistent findings. "
        "Useful for tracking remediation progress between scans."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "session_a": {
                "type": "string",
                "description": "First session directory name (e.g. '20260315_120000')",
            },
            "session_b": {
                "type": "string",
                "description": "Second session directory name (e.g. '20260318_140000')",
            },
        },
        "required": ["session_a", "session_b"],
    },
}
