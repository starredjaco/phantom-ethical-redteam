import os


def run(target: str, template: str = "instagram") -> str:
    template_path = os.path.join("tools", "zphisher_repo", "sites", template)
    if not os.path.exists(template_path):
        return "❌ Template Zphisher not found. Use a valid template (instagram, facebook...)"
    login_file = os.path.join(template_path, "login.html")
    with open(login_file, errors="ignore") as f:
        template_content = "Template Zphisher loaded (ethical) :\n" + f.read()[:500]
    return f"✅ Template {template} for {target} generated (NO REAL SEND POSSIBLE)\n{template_content}"

TOOL_SPEC = {
    "name": "generate_zphisher_template",
    "description": "Generate a template phishing with Zphisher ultra-realistic (educational purpose only)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "template": {"type": "string", "default": "instagram"}
        },
        "required": ["target"]
    }
}
