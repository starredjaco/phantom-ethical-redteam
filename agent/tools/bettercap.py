import platform
import subprocess


def _default_interface() -> str:
    """Return a sensible default network interface for the current OS."""
    if platform.system() == "Windows":
        return "Ethernet"
    return "eth0"


def run(interface: str = "", module: str = "net.probe", duration: int = 30) -> str:
    if platform.system() == "Windows":
        return "❌ Bettercap is not supported on Windows. Use WSL2 for network MITM."

    if not interface:
        interface = _default_interface()

    cmd = ["bettercap", "-iface", interface, "-caplet", module, "-timeout", str(duration)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return f"✅ Bettercap ({module}) ended on {interface}\nResume : {result.stdout[-300:]}"
    except Exception as e:
        return f"❌ Bettercap error : {str(e)}"

TOOL_SPEC = {
    "name": "run_bettercap",
    "description": "MITM, network probe, WiFi, Bluetooth (only in authorized lab)",
    "input_schema": {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "default": "eth0"},
            "module": {"type": "string", "default": "net.probe"},
            "duration": {"type": "integer", "default": 30}
        },
        "required": ["interface"]
    }
}
