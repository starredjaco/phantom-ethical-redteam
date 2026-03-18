import logging
import platform
import subprocess
from pathlib import Path

from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def run(target: str, role: str = "redteam", skill: str = "full-scan") -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    binary = PROJECT_ROOT / "bin" / "cyberstrike"
    if platform.system() == "Windows":
        binary = binary.with_suffix(".exe")

    if not binary.exists():
        return f"CyberStrikeAI binary not found at {binary}. Run the installer or build from source."

    output_path = log_path("cyberstrike.json")
    cmd = [str(binary), "--target", target, "--role", role, "--skill", skill, "--output", output_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        logger.info("CyberStrikeAI completed (role=%s, skill=%s)", role, skill)
        return f"CyberStrikeAI done (role={role})\n{result.stdout[-400:]}"
    except Exception as e:
        logger.error("CyberStrikeAI error: %s", e)
        return f"CyberStrikeAI error: {str(e)}"


TOOL_SPEC = {
    "name": "run_cyberstrike",
    "description": "Orchestrator AI-native 100+ outils (CyberStrikeAI) \u2013 mode redteam",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "role": {"type": "string", "default": "redteam"},
            "skill": {"type": "string", "default": "full-scan"},
        },
        "required": ["target"],
    },
}
