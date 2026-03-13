import subprocess

def run(interface: str = "eth0", module: str = "net.probe", duration: int = 30) -> str:
    cmd = ["bettercap", "-iface", interface, "-caplet", module, "-timeout", str(duration)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return f"✅ Bettercap ({module}) ended on {interface}\nResume : {result.stdout[-300:]}"
    except Exception as e:
        return f"❌ Bettercap errrr : {str(e)}"

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
