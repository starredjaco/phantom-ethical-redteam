import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
LOGS_DIR = Path("logs")


def run(filename: str = "") -> str:
    """Read a result file from logs/ or list all available log files."""
    logs_abs = LOGS_DIR.resolve()

    if not filename:
        entries = []
        for path in sorted(logs_abs.rglob("*")):
            if path.is_file():
                rel = path.relative_to(logs_abs)
                size = path.stat().st_size
                entries.append(f"  {rel} ({size} bytes)")
        if not entries:
            return "logs/ is empty"
        return "Available logs:\n" + "\n".join(entries)

    # Security: resolve symlinks and block path traversal
    try:
        target = (LOGS_DIR / filename).resolve(strict=True)
    except (OSError, ValueError):
        return f"File not found: {filename}"

    if not str(target).startswith(str(logs_abs)):
        return "Access denied: path outside logs/"

    try:
        content = target.read_text(encoding="utf-8", errors="replace")

        if not content.strip():
            return f"{filename}: (empty)"

        if filename.endswith(".json"):
            lines = [l.strip() for l in content.splitlines() if l.strip()]

            parsed = []
            for line in lines:
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            if len(parsed) > 1:
                summary = f"{filename} \u2013 {len(parsed)} entries:\n"
                for entry in parsed[:20]:
                    if "info" in entry:
                        cve_list = (entry.get("info", {}).get("classification") or {}).get("cve-id") or []
                        cve = cve_list[0] if cve_list else entry.get("template-id", "")
                        name = entry.get("info", {}).get("name", "?")
                        sev = entry.get("info", {}).get("severity", "?").upper()
                        host = entry.get("matched-at", entry.get("host", "?"))
                        summary += f"  [{sev}] {cve or name} \u2192 {host}\n"
                    else:
                        summary += f"  {json.dumps(entry)[:120]}\n"
                if len(parsed) > 20:
                    summary += f"  ... +{len(parsed) - 20} more"
                return summary.strip()

            if len(parsed) == 1:
                data = parsed[0]
                results = data.get("results", [])
                if results:
                    summary = f"{filename} \u2013 {len(results)} results:\n"
                    for r in results[:20]:
                        status = r.get("status", "?")
                        url = r.get("url", (r.get("input") or {}).get("FUZZ", "?"))
                        length = r.get("length", "?")
                        summary += f"  [{status}] {url} ({length}b)\n"
                    if len(results) > 20:
                        summary += f"  ... +{len(results) - 20} more"
                    return summary.strip()
                return f"{filename}:\n{json.dumps(data, indent=2)[:3000]}"

        # Plain text
        if len(content) > 3000:
            return f"{filename} (first 3000 chars):\n{content[:3000]}\n..."
        return f"{filename}:\n{content}"

    except Exception as e:
        logger.error("Error reading %s: %s", filename, e)
        return f"Error reading {filename}: {str(e)}"


TOOL_SPEC = {
    "name": "read_log",
    "description": (
        "Read a result file from logs/ (nuclei, ffuf, sqlmap, recon, etc.) "
        "or list all available log files. Call with no argument to list files."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": (
                    "Filename to read (e.g. 'nuclei.json', 'ffuf.json', 'sqlmap/target/log'). "
                    "Leave empty to list all available log files."
                ),
            }
        },
        "required": [],
    },
}
