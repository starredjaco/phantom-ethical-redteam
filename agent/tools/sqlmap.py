import subprocess

def run(url: str, level: int = 3, risk: int = 3) -> str:
    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk), "--output-dir", "logs/sqlmap"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return f"✅ sqlmap terminé\n{result.stdout[-500:]}"
    except Exception as e:
        return f"❌ Error sqlmap : {str(e)}"

TOOL_SPEC = {
    "name": "run_sqlmap",
    "description": "Injection SQL automated (level & risk configurables)",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "level": {"type": "integer", "default": 3},
            "risk": {"type": "integer", "default": 3}
        },
        "required": ["url"]
    }
}
