"""Authentication configuration for targeting protected endpoints."""

import json
import logging
import os

from .logs_helper import log_path

logger = logging.getLogger(__name__)


def _auth_file() -> str:
    return log_path("auth.json")


def _load_auth() -> dict:
    path = _auth_file()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_auth(data: dict):
    with open(_auth_file(), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_auth_headers(target: str = None) -> dict:
    """Return HTTP headers dict for the given target (or global auth)."""
    data = _load_auth()
    config = data.get(target) or data.get("_global")
    if not config:
        return {}

    auth_type = config.get("type", "")
    value = config.get("value", "")

    if auth_type == "bearer":
        return {"Authorization": f"Bearer {value}"}
    elif auth_type == "basic":
        return {"Authorization": f"Basic {value}"}
    elif auth_type == "cookie":
        return {"Cookie": value}
    elif auth_type == "header":
        # value format: "Header-Name: header-value"
        if ":" in value:
            name, _, val = value.partition(":")
            return {name.strip(): val.strip()}
    return {}


def run(auth_type: str, value: str, target: str = "") -> str:
    if auth_type not in ("bearer", "basic", "cookie", "header"):
        return "Unknown auth_type. Use: bearer, basic, cookie, header"

    data = _load_auth()
    key = target if target else "_global"
    data[key] = {"type": auth_type, "value": value}
    _save_auth(data)

    scope = f"target '{target}'" if target else "all targets (global)"
    logger.info("Auth configured: %s %s for %s", auth_type, scope, key)
    return f"Auth configured: {auth_type} for {scope}. Stored in session auth.json."


TOOL_SPEC = {
    "name": "configure_auth",
    "description": (
        "Configure authentication for protected targets. "
        "Supports bearer tokens, basic auth, cookies, and custom headers. "
        "Other tools will automatically use these credentials."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "auth_type": {
                "type": "string",
                "description": "Auth type: bearer, basic, cookie, header",
            },
            "value": {
                "type": "string",
                "description": "Auth value (token, base64 creds, cookie string, or 'Header-Name: value')",
            },
            "target": {
                "type": "string",
                "description": "Target domain (leave empty for global auth)",
            },
        },
        "required": ["auth_type", "value"],
    },
}
