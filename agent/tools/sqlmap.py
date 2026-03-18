"""Automated SQL injection detection and exploitation (sqlmap)."""

import os
import logging
import subprocess
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)


def run(url: str, level: int = 3, risk: int = 3, timeout: int = 300) -> str:
    guard = scope_guard(url)
    if guard:
        return guard

    output_dir = log_path("sqlmap")
    os.makedirs(output_dir, exist_ok=True)
    cmd = [
        "sqlmap", "-u", url, "--batch",
        "--level", str(level), "--risk", str(risk),
        "--output-dir", output_dir,
    ]

    logger.info("Running sqlmap: %s (level=%d, risk=%d)", url, level, risk)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        logger.info("sqlmap completed on %s", url)
        return f"sqlmap done\n{result.stdout[-500:]}"
    except subprocess.TimeoutExpired:
        logger.warning("sqlmap timed out after %ds on %s", timeout, url)
        return f"sqlmap timed out after {timeout}s \u2014 increase timeout parameter if needed"
    except FileNotFoundError:
        return "sqlmap not found. Install with: apt install sqlmap (Linux) or pip install sqlmap"
    except Exception as e:
        logger.error("sqlmap error: %s", e)
        return f"sqlmap error: {str(e)}"


TOOL_SPEC = {
    "name": "run_sqlmap",
    "description": "Automated SQL injection detection and exploitation (level, risk and timeout configurable)",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "level": {"type": "integer", "default": 3},
            "risk": {"type": "integer", "default": 3},
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Max execution time in seconds",
            },
        },
        "required": ["url"],
    },
}
