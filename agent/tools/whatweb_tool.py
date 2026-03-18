"""Web technology fingerprinting (WhatWeb + fallback)."""

import json
import logging
import subprocess

import requests
from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)

# Signatures for Python-based fallback fingerprinting
CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["Drupal", "sites/default", "drupal.js"],
    "Joomla": ["Joomla", "/administrator/", "com_content"],
    "Magento": ["Magento", "mage/", "varien"],
    "Laravel": ["laravel_session", "csrf-token"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "React": ["react-root", "data-reactroot", "__REACT"],
    "Vue.js": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "ng-app"],
}


def _fallback_fingerprint(target: str) -> str:
    """Python-based fingerprinting when whatweb is not available."""
    if not target.startswith("http"):
        target = f"https://{target}"

    results = []

    try:
        resp = requests.get(target, timeout=10, allow_redirects=True, verify=False)
        headers = resp.headers
        body = resp.text[:50000]

        # Server headers
        if headers.get("Server"):
            results.append(f"Server: {headers['Server']}")
        if headers.get("X-Powered-By"):
            results.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if headers.get("X-Generator"):
            results.append(f"X-Generator: {headers['X-Generator']}")
        if headers.get("X-AspNet-Version"):
            results.append(f"ASP.NET: {headers['X-AspNet-Version']}")

        # CMS detection
        for cms, sigs in CMS_SIGNATURES.items():
            if any(sig.lower() in body.lower() for sig in sigs):
                results.append(f"CMS/Framework: {cms}")

        # Security headers
        security_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                          "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]
        if present:
            results.append(f"Security headers present: {', '.join(present)}")
        if missing:
            results.append(f"Security headers MISSING: {', '.join(missing)}")

    except Exception as e:
        results.append(f"Main page error: {e}")

    # Check robots.txt
    try:
        r = requests.get(f"{target}/robots.txt", timeout=5, verify=False)
        if r.status_code == 200 and len(r.text) > 10:
            results.append(f"robots.txt: found ({len(r.text)} bytes)")
    except Exception:
        pass

    # Check sitemap.xml
    try:
        r = requests.get(f"{target}/sitemap.xml", timeout=5, verify=False)
        if r.status_code == 200 and "xml" in r.text[:200].lower():
            results.append(f"sitemap.xml: found ({len(r.text)} bytes)")
    except Exception:
        pass

    if not results:
        return "No technology fingerprints detected."
    return "Technology fingerprint (Python fallback):\n" + "\n".join(f"  {r}" for r in results)


def run(target: str, aggression: int = 1) -> str:
    guard = scope_guard(target)
    if guard:
        return guard

    output_path = log_path("whatweb.json")

    try:
        cmd = ["whatweb", f"-a{aggression}", f"--log-json={output_path}", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 and result.stdout.strip():
            logger.info("WhatWeb scan completed for %s", target)
            return f"WhatWeb scan ({target}):\n{result.stdout[:2000]}"

        # Try parsing JSON output
        try:
            with open(output_path, encoding="utf-8") as f:
                data = json.load(f)
            return f"WhatWeb scan ({target}):\n{json.dumps(data, indent=2)[:2000]}"
        except Exception:
            pass

        return f"WhatWeb returned no results.\n{result.stderr[:300]}"

    except FileNotFoundError:
        logger.info("WhatWeb not found, using Python fallback for %s", target)
        return _fallback_fingerprint(target)
    except Exception as e:
        logger.warning("WhatWeb failed (%s), using fallback: %s", target, e)
        return _fallback_fingerprint(target)


TOOL_SPEC = {
    "name": "run_whatweb",
    "description": (
        "Web technology fingerprinting \u2014 detect CMS, frameworks, server software, "
        "security headers. Uses WhatWeb if available, otherwise Python-based fallback."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target URL or domain"},
            "aggression": {
                "type": "integer",
                "default": 1,
                "description": "Aggression level 1-4 (1=stealthy, 4=aggressive)",
            },
        },
        "required": ["target"],
    },
}
