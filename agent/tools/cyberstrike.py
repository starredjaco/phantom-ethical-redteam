import os
import platform
import subprocess


def run(target: str, role: str = "redteam", skill: str = "full-scan") -> str:
    binary = os.path.join("bin", "cyberstrike")
    if platform.system() == "Windows":
        binary += ".exe"
    output_path = os.path.join("logs", "cyberstrike.json")
    cmd = [binary, "--target", target, "--role", role, "--skill", skill, "--output", output_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return f"✅ CyberStrikeAI done (role={role})\n{result.stdout[-400:]}"
    except Exception as e:
        return f"❌ CyberStrikeAI error : {str(e)} (verify go build)"

TOOL_SPEC = {
    "name": "run_cyberstrike",
    "description": "Orchestrator AI-native 100+ outils (CyberStrikeAI) – mode redteam",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "role": {"type": "string", "default": "redteam"},
            "skill": {"type": "string", "default": "full-scan"}
        },
        "required": ["target"]
    }
}
